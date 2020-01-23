#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <arpa/inet.h>
#include <ndpi/ndpi_api.h>
#include <syslog.h>
#include <ndpi/ndpi_typedefs.h>
#include "ndff.h"
#include "ndff_util.h"

static inline u_int16_t ndff_detect_type_en(const u_int16_t eth_offset, const u_char *packet, u_int16_t *type)
{
    struct ndpi_ethhdr *l2header = (struct ndpi_ethhdr*) &packet[eth_offset];
    u_int16_t ip_offset = eth_offset + sizeof(struct ndpi_ethhdr);

    /* <= 1500: payload length, >= 1536: protocol type */
    u_int16_t payload_length = ntohs(l2header->h_proto);
    if (payload_length > 1500)
    {
        if (payload_length >= 1536)
        {
            *type = payload_length;
        }
        payload_length = 0;
    }
    if (payload_length != 0)
    {
        struct ndpi_llc_header_snap *llc = (struct ndpi_llc_header_snap*) &packet[ip_offset];
        if (llc->dsap == SNAP || llc->ssap == SNAP)
        {
            *type = llc->snap.proto_ID;
            ip_offset += 8;
        }
    }
    return ip_offset;
}

static inline u_int16_t ndff_detect_type_wlan(const u_int16_t eth_offset, const u_char *packet, u_int16_t *type, char **errmsg)
{
    struct ndpi_radiotap_header *radio = (struct ndpi_radiotap_header*) &packet[eth_offset];
    if ((radio->flags & BAD_FCS) == BAD_FCS)
    {
        *errmsg = "Malformed Packet";
        return 0;
    }
    struct ndpi_wifi_header *wlan = (struct ndpi_wifi_header*) &packet[eth_offset + radio->len];

    /* Calculate header length */
    u_int16_t frame_control = wlan->fc;
    u_int16_t wifi_len = 0;
    if (FCF_TYPE(frame_control) == WIFI_DATA)
    {
        if ((FCF_TO_DS(frame_control) && FCF_FROM_DS(frame_control) == 0x0) ||
            (FCF_TO_DS(frame_control) == 0x0 && FCF_FROM_DS(frame_control)))
        {
            wifi_len = 26;
        }
    }
    else
    {
        *errmsg = "No data frame";
        return 0;
    }
    struct ndpi_llc_header_snap *llc = (struct ndpi_llc_header_snap*) &packet[eth_offset + radio->len + wifi_len];
    if (llc->dsap == SNAP)
    {
        *type = ntohs(llc->snap.proto_ID);
    }
    return eth_offset + radio->len + wifi_len + sizeof(struct ndpi_llc_header_snap);
}

u_int16_t ndff_detect_type(const struct pcap_pkthdr *header, const int datalink_type, const u_int16_t eth_offset, const u_char *packet, u_int16_t *type, u_int16_t *vlan_id, char **errmsg)
{
    *errmsg = NULL;
    struct ndpi_chdlc *chdlc;
    union {
        u_int32_t u32;
        struct ndpi_mpls_header mpls;
    } mpls;
    u_int16_t ip_offset = 0;
    *vlan_id = 0;
    switch (datalink_type)
    {
    /* DLT_NULL means BSD loopback encapsulation.
     * L2 layer contains a 4 bytes field, and its value indicates the upper (I mean, L3) protocol.
     * 2 means IPv4, 24 or 30 for IPv6, 7 for OSI packets, and 23 for IPX.
     * In practice, we don't need to consider OSI/IPX packets, so for simplicity return ETH_PROTO_IPv4 (0x0800) for 2 and ETH_PROTO_IPv6 (0x86dd) otherwise (IPv6)
     */
    case DLT_NULL:
        *type = ntohl(*((u_int32_t*) &packet[eth_offset])) == 2 ? ETH_PROTO_IPv4 : ETH_PROTO_IPv4;
        ip_offset = eth_offset + 4;
        break;
    /*
     * Handling PPP in HDLC-like framing or Cisco PPP with HDLC framing.
     * Both PPP in HDLC-like framing, as per RFC-1662, and Cisco PPP with HDLC framing contains 3 field.
     * They differ in theier first 16 bits, but here we consider the rest 16 bits (protocol).
     */
    case DLT_PPP_SERIAL:
    case DLT_C_HDLC:
        chdlc = (struct ndpi_chdlc*) &packet[eth_offset];
        *type = ntohs(chdlc->proto_code);
        ip_offset = eth_offset + sizeof(struct ndpi_chdlc);
        break;
    /*
     * Linux Cooked capture encapsulatation contains 16 Octats (i.e. 16 bytes) header.
     * Here what we'd like to get is the L3 protocol type, so we only see the last 2 bytes.
     * See https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html for more details.
     */
    case DLT_LINUX_SLL:
        *type = (packet[eth_offset + 14] << 8) + packet[eth_offset + 15];
        ip_offset = eth_offset + 16;
        break;
    /*
     * DLT_RAW doesn't have L2 header.
     */
    case DLT_RAW:
        ip_offset = 0;
        break;
    case DLT_EN10MB:
        ip_offset = ndff_detect_type_en(eth_offset, packet, type);
        break;
    case DLT_IEEE802_11_RADIO:
        ip_offset = ndff_detect_type_wlan(eth_offset, packet, type, errmsg);
        break;
    default:
        *errmsg= "Unknown Data Link Type";
        break;
    }

    if (*type == ETH_PROTO_VLAN)
    {
        *vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset + 1]) & 0xFFF;
        *type = (packet[ip_offset + 2] << 8) + packet[ip_offset + 3];
        ip_offset += 4;
        while ((*type == ETH_PROTO_VLAN) && (ip_offset < header->caplen))
        {
            *vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset + 1]) & 0xFFF;
            *type = (packet[ip_offset + 2] << 8) + packet[ip_offset + 3];
            ip_offset += 4;
        }
    }
    else if (*type == PROTO_MPLS_UNICAST || *type == PROTO_MPLS_MULTICAST)
    {
        mpls.u32 = *((u_int32_t*) &packet[ip_offset]);
        mpls.u32 = ntohl(mpls.u32);
        *type = ETH_PROTO_IPv4;
        ip_offset += 4;
        while (!mpls.mpls.s)
        {
            mpls.u32 = *((u_int32_t*) &packet[ip_offset]);
            mpls.u32 = ntohl(mpls.u32);
            ip_offset += 4;
        }
    }
    else if (*type == PPPoE)
    {
        *type = ETH_PROTO_IPv4;
        ip_offset += 8;
    }
    return ip_offset;
}

u_int16_t ndff_set_iphdr(const struct pcap_pkthdr *header, const u_int16_t type, const u_char *packet, const u_int16_t offset, struct ndpi_iphdr **ipv4, struct ndpi_ipv6hdr **ipv6, u_int8_t *proto)
{
    struct ndpi_iphdr *_ipv4;
    struct ndpi_ipv6hdr *_ipv6;
    u_int16_t frag_off = 0, iphdr_len;

    _ipv4 = (struct ndpi_iphdr*) &packet[offset];
    if (type == ETH_PROTO_IPv4 && header->caplen >= offset)
    {
        frag_off = ntohs(_ipv4->frag_off);
        if (header->caplen < header->len)
        {
            ndff_log(LOG_WARNING, "[WARN] packet capture size is smaller than packet size.");
        }
    }
    if (_ipv4->version == IPVERSION)
    {
        iphdr_len = ((u_int16_t) _ipv4->ihl) * 4;
        *proto = _ipv4->protocol;
        if (_ipv4->protocol == IPPROTO_IPv6)
        {
            return ndff_set_iphdr(header, ETH_PROTO_IPv6, packet, offset + iphdr_len, ipv4, ipv6, proto);
        }
        if ((frag_off & 0x1FFF) != 0)
        {
            ndff_log(LOG_NOTICE, "[NOTICE] IP packet fragmentation is not supported.");
        }
        *ipv4 = _ipv4;
        *ipv6 = NULL;
        return offset + iphdr_len;
    }
    else if (_ipv4->version == 6)
    {
        _ipv6 = (struct ndpi_ipv6hdr*) &packet[offset];
        *proto = _ipv6->ip6_hdr.ip6_un1_nxt;
        iphdr_len = sizeof(struct ndpi_ipv6hdr);
        if (*proto == IPPROTO_DSTOPTS)
        {
            u_int8_t *options = (u_int8_t*) &packet[offset + iphdr_len];
            *proto = options[0];
            iphdr_len += 8 * (options[1] + 1);
        }
        *ipv4 = NULL;
        *ipv6 = _ipv6;
        return offset + iphdr_len;
    }
    else
    {
        ndff_log(LOG_INFO, "[INFO] Only IPv4/v6 packets are supported.");
        *ipv4 = NULL;
        *ipv6 = NULL;
        return offset;
    }
}

u_int16_t ndff_set_l4hdr(
        const struct pcap_pkthdr *header, const u_char *packet,
        const u_int16_t offset, const struct ndpi_iphdr *iph, const struct ndpi_ipv6hdr *iph6, u_int8_t proto,
        struct ndpi_tcphdr **tcph, struct ndpi_udphdr **udph, u_int16_t *src_port, u_int16_t *dst_port, u_int8_t **payload, u_int16_t *payload_len
)
{
    u_int32_t l4_offset;
    u_int16_t ip_offset;
    u_int16_t l4_packet_len;
    u_int16_t ipsize;

    const u_int8_t *l3, *l4;
    if (iph)
    {
        ip_offset = offset - iph->ihl * 4;
        ipsize = header->caplen - ip_offset;
        if (ipsize < 20)
            return offset;
        if ((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len))
            return offset;
        l4_packet_len = iph->tot_len - (iph->ihl * 4);
        l4_offset = iph->ihl * 4;
        l3 = (const u_int8_t*) iph;
        
    }
    else
    {
        ip_offset = offset - sizeof(struct ndpi_ipv6hdr);
        ipsize = header->caplen - ip_offset;
        l4_packet_len = iph6->ip6_hdr.ip6_un1_plen;
        l4_offset = ntohs(sizeof(struct ndpi_ipv6hdr));
        l3 = (const u_int8_t*) iph6;
    }

    l4 = &((const u_int8_t *) l3)[l4_offset];

    if (proto == IPPROTO_TCP && l4_packet_len >= sizeof(struct ndpi_tcphdr))
    {
        u_int tcp_len;
        *tcph = (struct ndpi_tcphdr*) l4;
        *src_port = ntohs((*tcph)->source);
        *dst_port = ntohs((*tcph)->dest);
        tcp_len = ndpi_min(4 * (*tcph)->doff, l4_packet_len);
        *payload = (u_int8_t*) &l4[tcp_len];
        *payload_len = ndpi_max(0, l4_packet_len - 4 * (*tcph)->doff);
        offset += tcp_len;
    }
    else if (proto == IPPROTO_UDP && l4_packet_len >= sizeof(struct ndpi_udphdr))
    {
        *udph = (struct ndpi_udphdr*) l4;
        *src_port = ntohs((*udph)->source);
        *dst_port = ntohs((*udph)->dest);
        *payload = (u_int8_t*) &l4[sizeof(struct ndpi_udphdr)];
        *payload_len = (l4_packet_len > sizeof(struct ndpi_udphdr)) ? l4_packet_len - sizeof(struct ndpi_udphdr) : 0;
        offset += sizeof(struct ndpi_udphdr);
    }
    else if (proto == IPPROTO_ICMP)
    {
        *src_port = 0; *dst_port = 0;
        *payload = (u_int8_t*) &l4[sizeof(struct ndpi_icmphdr)];
        *payload_len = (l4_packet_len > sizeof(struct ndpi_icmphdr)) ? l4_packet_len - sizeof(struct ndpi_icmphdr) : 0;
        offset += sizeof(struct ndpi_icmphdr);
    }
    else if (proto == IPPROTO_ICMPV6)
    {
        *src_port = 0; *dst_port = 0;
        *payload = (u_int8_t*) &l4[sizeof(struct ndpi_icmp6hdr)];
        *payload_len = (l4_packet_len > sizeof(struct ndpi_icmp6hdr)) ? l4_packet_len - sizeof(struct ndpi_icmp6hdr) : 0;
        offset += sizeof(struct ndpi_icmp6hdr);
    }
    else
    {
        *src_port = *dst_port = 0;
    }
    
    return offset;
}


#ifdef __cplusplus
}
#endif /* __cplusplus */
