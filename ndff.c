#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <arpa/inet.h>
#include <ndpi/ndpi_api.h>
#include <syslog.h>
#include <ndpi/ndpi_typedefs.h>
#include <ndpi/ndpi_protocol_ids.h>
#include "ndff.h"
#include "ndff_util.h"

static u_int32_t flow_id = 0;
static u_int8_t max_tcp_dissected_packets = 80, max_udp_dissected_packets = 16;

static inline void ndff_patchIPv6Address(char *str) {
  int i = 0, j = 0;

  while(str[i] != '\0') {
    if((str[i] == ':')
       && (str[i+1] == '0')
       && (str[i+2] == ':')) {
      str[j++] = ':';
      str[j++] = ':';
      i += 3;
    } else
      str[j++] = str[i++];
  }

  if(str[j] != '\0') str[j] = '\0';
}

static inline u_int8_t ndff_is_secured_protocol(struct ndff_flow *flow)
{
    if ((flow->detected_protocol.master_protocol == NDPI_PROTOCOL_TLS)
        || (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_TLS)
        || (flow->detected_protocol.master_protocol == NDPI_PROTOCOL_SSH)
        || (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_SSH)
   )
   {
       return 1;
   }
   else
   {
       return 0;
   }
}

static inline u_int8_t is_proto(struct ndff_flow *flow, u_int16_t id)
{
	return (flow->detected_protocol.master_protocol == id) || (flow->detected_protocol.app_protocol == id);
}

static inline void ndff_collected_info(struct ndff_flow *flow, ndff_callback on_detect, ndff_callback on_giveup)
{
    if (!flow->ndpi_flow)
        return;
    
    snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s", flow->ndpi_flow->host_server_name);
	if (is_proto(flow, NDPI_PROTOCOL_BITTORRENT))
	{
		u_int i, j, n = 0;
		for (i = 0, j = 0; j < sizeof(flow->bittorrent_hash) - 1; ++i)
		{
			sprintf(&flow->bittorrent_hash[j], "%02x", flow->ndpi_flow->protos.bittorrent.hash[i]);
			j += 2;
			n += flow->ndpi_flow->protos.bittorrent.hash[i];
		}
		if (n == 0) flow->bittorrent_hash[0] = '\0';
	}
	else if (is_proto(flow, NDPI_PROTOCOL_HTTP))
	{
		if (flow->ndpi_flow->http.url != NULL)
		{
			snprintf(flow->http.url, sizeof(flow->http.url), "%s", flow->ndpi_flow->http.url);
			snprintf(flow->http.user_agent, sizeof(flow->http.user_agent), "%s", flow->ndpi_flow->http.user_agent ? flow->ndpi_flow->http.user_agent : "");
		}
	}
	else if (is_proto(flow, NDPI_PROTOCOL_SSH))
	{
		snprintf(flow->ssh_tls.client_requested_server_name, sizeof(flow->ssh_tls.client_requested_server_name), "%s", flow->ndpi_flow->protos.ssh.client_signature);
	}
	else if (is_proto(flow, NDPI_PROTOCOL_TLS))
	{
		snprintf(flow->ssh_tls.client_requested_server_name, sizeof(flow->ssh_tls.client_requested_server_name), "%s", flow->ndpi_flow->protos.stun_ssl.ssl.client_requested_server_name);
	}
	else if (is_proto(flow, NDPI_PROTOCOL_DHCP))
	{
		flow->dhcp.yiaddr = flow->ndpi_flow->protos.dhcp.yiaddr;
		flow->dhcp.lease_time = flow->ndpi_flow->protos.dhcp.lease_time;
		memcpy(flow->dhcp.macaddr, flow->ndpi_flow->protos.dhcp.macaddr, 6);
	}
	else if (is_proto(flow, NDPI_PROTOCOL_DNS))
	{
		flow->dns.query_type = flow->ndpi_flow->protos.dns.query_type;
		flow->dns.rsp_type = flow->ndpi_flow->protos.dns.rsp_type;
		if (flow->ndpi_flow->protos.dns.rsp_type == 28)
		{
			memcpy(&flow->dns.rsp_addr.ipv6, &flow->ndpi_flow->protos.dns.rsp_addr.ipv6, sizeof(struct ndpi_in6_addr));
		}
		else
		{
			memcpy(&flow->dns.rsp_addr.ipv4, &flow->ndpi_flow->protos.dns.rsp_addr.ipv4, sizeof(u_int32_t));
		}
	}

	if (flow->is_detection_completed)
	{
		if (on_giveup != NULL)
		{
			on_giveup(flow, NULL);
		}
		if (on_detect != NULL)
		{
			on_detect(flow, NULL);
		}
	}
	if (flow->ndpi_flow)
	{
		ndpi_flow_free(flow->ndpi_flow);
		flow->ndpi_flow = NULL;
	}
	if (flow->src_id)
	{
		ndpi_free(flow->src_id);
		flow->src_id = NULL;
	}
	if (flow->dst_id)
	{
		ndpi_free(flow->dst_id);
		flow->dst_id = NULL;
	}
}

// ensure that flow is not NULL.
struct ndpi_proto ndff_get_protocol(
    struct ndpi_detection_module_struct *detect_mod, u_int8_t proto_num, u_int64_t time,
    struct ndpi_iphdr *iph, struct ndpi_ipv6hdr *iph6, u_int16_t ipsize,
    struct ndpi_id_struct *src, struct ndpi_id_struct *dst,
    ndff_callback on_detect, ndff_callback on_giveup,
    struct ndff_flow *flow)
{
    if (flow->first_seen == 0)
    {
        flow->first_seen = time;
    }
    flow->last_seen = time;
    if (!flow->is_detection_completed)
    {
        u_int enough = (
            (proto_num == IPPROTO_UDP && (flow->out_packets + flow->in_packets) > max_udp_dissected_packets)
            || (proto_num == IPPROTO_TCP && (flow->out_packets + flow->in_packets) > max_tcp_dissected_packets)
        ) ? 1 : 0;
        flow->detected_protocol = ndpi_detection_process_packet(detect_mod, flow->ndpi_flow, iph != NULL ? (u_int8_t*) iph : (u_int8_t*) iph6, ipsize, time, src, dst);
        if (enough || flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
        {
            if (enough || !ndpi_extra_dissection_possible(detect_mod, flow->ndpi_flow))
            {
                flow->is_detection_completed = 1;
                if (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN)
                {
                    u_int8_t proto_guessed;
                    flow->detected_protocol = ndpi_detection_giveup(detect_mod, flow->ndpi_flow, 1, &proto_guessed);
                }
                ndff_collected_info(flow, on_detect, on_giveup);
            }
        }
    }
    return flow->detected_protocol;
}

struct ndff_flow *ndff_get_flow_info(
	void **trees,
	u_int32_t num_trees,
	u_int16_t vlan_id,
    u_int32_t rawsize,
    struct ndpi_id_struct **src, struct ndpi_id_struct **dst,
	struct ndpi_iphdr *iph, struct ndpi_ipv6hdr *iph6, /* L3. iph shall be NULL if L3 protocol is IPv6. */
	struct ndpi_tcphdr *tcph, struct ndpi_udphdr *udph /* L4. tcph shall be NULL if L4 protocol is TCP */
)
{
	struct ndff_flow flow;
    u_int32_t hash_value, i, transaction_id;
	u_int8_t *l4;
    u_int16_t sport, dport;
    int is_swapped;
    void *node;
	transaction_id = 0;

    if (tcph)
    {
        flow.src_port = sport = ntohs(tcph->source);
        flow.dst_port = dport = ntohs(tcph->dest);
    }
    else if (udph)
    {
        flow.src_port = sport = ntohs(udph->source);
        flow.dst_port = dport = ntohs(udph->dest);
		if (flow.dst_port == 67 || flow.dst_port == 68 || flow.src_port == 67 || flow.src_port == 68)
		{
			l4 = (u_int8_t*) udph;
			if ((l4[8] == 0x02 || l4[8] == 0x01) && l4[9] == 0x01 && l4[10] == 0x06 && l4[11] == 0x00)
			{
				transaction_id = ((u_int32_t) l4[12] << 24) | (l4[13] << 16) | (l4[14] << 8) | l4[15];
			}
		}
	}
    else
    {
        sport = 0; dport = 0;
    }
	flow.transaction_id = transaction_id;
    
    /* calculate hash */
    flow.vlan_id = vlan_id;
    if (iph)
    {
        flow.protocol = iph->protocol;
        flow.src_ip = iph->saddr; flow.dst_ip = iph->daddr;
        flow.hash_value = hash_value = flow.protocol + flow.vlan_id + flow.src_ip + flow.dst_ip + flow.src_port + flow.dst_port + transaction_id;
    }
    else
    {
        flow.protocol = iph6->ip6_hdr.ip6_un1_nxt;
        if (flow.protocol == IPPROTO_DSTOPTS)
        {
            const u_int8_t *options = (const u_int8_t*) iph6 + sizeof(const struct ndpi_ipv6hdr);
            flow.protocol = options[0];
        }
        flow.src_ip = iph6->ip6_src.u6_addr.u6_addr32[2] + iph6->ip6_src.u6_addr.u6_addr32[3];
        flow.dst_ip = iph6->ip6_dst.u6_addr.u6_addr32[2] + iph6->ip6_dst.u6_addr.u6_addr32[3];
        flow.hash_value = hash_value = flow.protocol + flow.vlan_id + flow.src_ip + flow.dst_ip + flow.src_port + flow.dst_port + transaction_id;
    }
    i = hash_value % num_trees;
    node = ndpi_tfind(&flow, &trees[i], ndff_flow_node_cmp);

    is_swapped = 0;
    if (node == NULL)
    {
        /* Swap src with dst, and then try to find a flow node in a binary search tree */
        u_int32_t _sip = flow.src_ip;
        u_int32_t _dip = flow.dst_ip;
        u_int16_t _sp = flow.src_port;
        u_int16_t _dp = flow.dst_port;

        flow.src_ip = _dip;
        flow.dst_ip = _sip;
        flow.src_port = _dp;
        flow.dst_port = _sp;
        is_swapped = 1;

        node = ndpi_tfind(&flow, &trees[i], ndff_flow_node_cmp);
    }    

    /*
     * If the incomign flow node isn't in a binary search tree, memory will be allocated to store the flow node therein
     * Otherwise, the exisiting flow node is used and updated.
     */
    if (node == NULL)
    {
        struct ndff_flow *new_flow = (struct ndff_flow*) malloc(sizeof(struct ndff_flow));
        if (new_flow == NULL)
        {
            // TODO: error handling. Low mem.
        }
        else
        {
            memset(new_flow, 0, sizeof(struct ndff_flow));
            new_flow->flow_id = flow_id++;
            new_flow->hash_value = hash_value;
            new_flow->protocol = flow.protocol;
            // in this branch, is_swapped must be 1.
            new_flow->src_ip = flow.dst_ip;
            new_flow->src_port = flow.dst_port;
            new_flow->dst_ip = flow.src_ip;
            new_flow->dst_port = flow.src_port;
            new_flow->is_detection_completed = 0;
            if (iph)
            {
                new_flow->ip_version = IPVERSION;
                inet_ntop(AF_INET, &new_flow->src_ip, new_flow->src_name, sizeof(new_flow->src_name));
                inet_ntop(AF_INET, &new_flow->dst_ip, new_flow->dst_name, sizeof(new_flow->dst_name));
            }
            else
            {
                new_flow->ip_version = 6;
                memcpy(new_flow->src_ipv6.u6_addr.u6_addr32, iph6->ip6_src.u6_addr.u6_addr32, sizeof(iph6->ip6_src.u6_addr.u6_addr32));
                memcpy(new_flow->dst_ipv6.u6_addr.u6_addr32, iph6->ip6_dst.u6_addr.u6_addr32, sizeof(iph6->ip6_dst.u6_addr.u6_addr32));
                inet_ntop(AF_INET6, &new_flow->src_ipv6, new_flow->src_name, sizeof(new_flow->src_name));
                inet_ntop(AF_INET6, &new_flow->dst_ipv6, new_flow->dst_name, sizeof(new_flow->dst_name));
                ndff_patchIPv6Address(new_flow->src_name); ndff_patchIPv6Address(new_flow->dst_name);
            }
            if ((new_flow->ndpi_flow = malloc(sizeof(struct ndpi_flow_struct))) == NULL)
            {
                free(new_flow);
                return NULL;
            }
            else
            {
                memset(new_flow->ndpi_flow, 0, sizeof(struct ndpi_flow_struct));
            }
            if ((new_flow->src_id = malloc(sizeof(struct ndpi_id_struct))) == NULL)
            {
                free(new_flow);
                return NULL;
            }
            else
            {
                memset(new_flow->src_id, 0, sizeof(struct ndpi_id_struct));
            }
            if ((new_flow->dst_id = malloc(sizeof(struct ndpi_id_struct))) == NULL)
            {
                free(new_flow);
                return NULL;
            }
            else
            {
                memset(new_flow->dst_id, 0, sizeof(struct ndpi_id_struct));
            }
            new_flow->out_packets = 1; new_flow->out_bytes = rawsize;
            new_flow->in_packets = 0; new_flow->in_packets = 0;
			new_flow->transaction_id = flow.transaction_id;
            // Insert into the binary tree.
            ndpi_tsearch(new_flow, &trees[i], ndff_flow_node_cmp);
            *src = new_flow->src_id; *dst = new_flow->dst_id;
            return new_flow;
        }
    }
    else
    {
        struct ndff_flow *_flow = *(struct ndff_flow**) node;
        u_int8_t is_reversed = 0;
        if (_flow->src_ip == flow.dst_ip)
        {
            is_reversed = 1;
        }
        if (is_swapped || is_reversed)
        {
            *src = _flow->dst_id; *dst = _flow->src_id;
            _flow->in_packets++;
            _flow->in_bytes += rawsize;
        }
        else
        {
            *src = _flow->src_id; *dst = _flow->dst_id;
            _flow->out_packets++;
            _flow->out_bytes += rawsize;
        }
        return _flow;
    }
    
	return NULL;
}

int ndff_flow_node_cmp(const void *lhs, const void *rhs)
{
	const struct ndff_flow *x = (const struct ndff_flow*) lhs;
	const struct ndff_flow *y = (const struct ndff_flow*) rhs;
	if (x->hash_value < y->hash_value)
	{
		return -1;
	}
	else if (x->hash_value > y->hash_value)
	{
		return 1;
	}
	else
	{
		/* Hashes match... */
		if (
			(x->src_ip == y->src_ip && x->src_port == y->src_port && x->dst_ip == y->dst_ip && x->dst_port == y->dst_port && x->transaction_id == y->transaction_id)
		 || (x->src_ip == y->dst_ip && x->src_port == y->dst_port && x->dst_ip == y->src_ip && x->dst_port == y->src_port && x->transaction_id == y->transaction_id)
		)
		{
			/* And IP:Port pairs match */
			return 0;
		}
		if (x->src_ip == y->dst_ip && x->dst_ip && y->src_ip)
		{
			if (x->src_port < y->dst_port)
			{
				return -1;
			}
			if (x->src_port > y->dst_port)
			{
				return 1;
			}
			if (x->dst_port < y->src_port)
			{
				return -1;
			}
			if (x->dst_port > y->src_port)
			{
				return 1;
			}
			if (x->transaction_id < y->transaction_id)
			{
				return -1;
			}
			if (x->transaction_id > y->transaction_id)
			{
				return 1;
			}
		}
		/* And source IP addrs differ */
		if (x->src_ip < y->src_ip)
		{
			return -1;
		}
		if (x->src_ip > y->src_ip)
		{
			return 1;
		}

		/* IP source IP addrs match, but source ports differ */
		if (x->src_port < y->src_port)
		{
			return -1;
		}
		if (x->src_port > y->src_port)
		{
			return 1;
		}

		/* Hahses, source IP addrs, and source ports match, but destination IP addrs differ */
		if (x->dst_ip < y->dst_ip)
		{
			return -1;
		}
		if (x->dst_ip > y->dst_ip)
		{
			return 1;
		}

		/* Hahses, source IP addrs, source ports, and destination IP addrs match, but dst ports differ */
		if (x->dst_port < y->dst_port)
		{
			return -1;
		}
		if (x->dst_port > y->dst_port)
		{
			return 1;
		}

		if (x->transaction_id < y->transaction_id)
		{
			return -1;
		}
		if (x->transaction_id > y->transaction_id)
		{
			return 1;
		}

		return 0;
		/*
		 * Actually, I don't give a damn about what ordering is defined in flows, as long as
		 * binary search tree works correctly and incoming flows are inserted in the tree practically randomly.
		 * (*Practical* randomness is required to balance the tree, or search would otherwise underperform)
		 */
	}
}

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
        u_int16_t offset, struct ndpi_iphdr *iph, struct ndpi_ipv6hdr *iph6, u_int8_t proto,
        struct ndpi_tcphdr **tcph, struct ndpi_udphdr **udph, u_int8_t **payload, u_int16_t *payload_len
)
{
    u_int32_t l4_offset;
    u_int16_t ip_offset;
    u_int16_t l4_packet_len;
    u_int16_t ipsize;

    const u_int8_t *l3, *l4;
    if (iph)
    {
        /* IPv4 */
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
        /* IPv6 */
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
        *udph = NULL;
        tcp_len = ndpi_min(4 * (*tcph)->doff, l4_packet_len);
        *payload = (u_int8_t*) &l4[tcp_len];
        *payload_len = ndpi_max(0, l4_packet_len - 4 * (*tcph)->doff);
        offset += tcp_len;
    }
    else if (proto == IPPROTO_UDP && l4_packet_len >= sizeof(struct ndpi_udphdr))
    {
        *udph = (struct ndpi_udphdr*) l4;
        *tcph = NULL;
        *payload = (u_int8_t*) &l4[sizeof(struct ndpi_udphdr)];
        *payload_len = (l4_packet_len > sizeof(struct ndpi_udphdr)) ? l4_packet_len - sizeof(struct ndpi_udphdr) : 0;
        offset += sizeof(struct ndpi_udphdr);
    }
    else
    {
        *tcph = *udph = NULL;
        if (proto == IPPROTO_ICMP)
        {
            *payload = (u_int8_t*) &l4[sizeof(struct ndpi_icmphdr)];
            *payload_len = (l4_packet_len > sizeof(struct ndpi_icmphdr)) ? l4_packet_len - sizeof(struct ndpi_icmphdr) : 0;
            offset += sizeof(struct ndpi_icmphdr);
        }
        else if (proto == IPPROTO_ICMPV6)
        {
            *payload = (u_int8_t*) &l4[sizeof(struct ndpi_icmp6hdr)];
            *payload_len = (l4_packet_len > sizeof(struct ndpi_icmp6hdr)) ? l4_packet_len - sizeof(struct ndpi_icmp6hdr) : 0;
            offset += sizeof(struct ndpi_icmp6hdr);
        }
    }
    
    return offset;
}


#ifdef __cplusplus
}
#endif /* __cplusplus */
