#ifndef _NDFF_H_
#define _NDFF_H_

#include <ndpi/ndpi_includes.h>
#include <pcap.h>
#include <stdbool.h>

#define ETH_PROTO_IPv4 0x0800
#define ETH_PROTO_IPv6 0x86dd
#define ETH_PROTO_VLAN 0x8100
#define PROTO_MPLS_UNICAST 0x8847
#define PROTO_MPLS_MULTICAST 0x8848
#define PPPoE 0x8864
#define SNAP 0xaa
#define BAD_FCS 0x50

#define FCF_TYPE(fc) (((fc) >> 2) & 0x3)
#define FCF_TO_DS(fc) ((fc) & 0x0100)
#define FCF_FROM_DS(fc) ((fc) & 0x0200)
#define WIFI_DATA 0x2

#define IPPROTO_TCP 6
#define IPPROTO_IPv6 41
#define IPPROTO_DSTOPTS 60

/**
 * @brief Detect upper layer protocol
 * @fn ndff_detect_type
 * @param[in] (header) Pcap Packet Header (Contains captured bytes length and timestamp)
 * @param[in] (datalink_type) ...
 * @param[in] (eth_offset) Offset from the start of a captured packet to the start of an ether frame
 * @param[in] (packet) Raw packet bytes captured by pcap
 * @param[out] (type) Detected type (e.g. IPv4)
 * @param[out] (vlan_id) Detected VLAN id. 0 if not detected.
 * @param[in,out] (errbuf) A string buffer where an error message is written in case of failure
 * @return Offset of the IP header, whether it be IPv4 or IPv6.
 */
u_int16_t ndff_detect_type(const struct pcap_pkthdr *header, const int datalink_type, const u_int16_t eth_offset, const u_char *packet,
        u_int16_t *type, u_int16_t *vlan_id, char **errbuf);

/**
 * @brief Search an IP header in a packet bytes and set an address of IPv4 or IPv6 header to ipv4/ipv6 params.
 * @fn ndff_set_iphdr
 * @param[in] (header) Pcap Packet Header (Contains captured bytes length and timestamp)
 * @param[in] (type) Detected packet type (e.g. IPv4)
 * @param[in] (packet) Raw packet bytes captured by pcap
 * @param[in] (offset) Offset to the IP header from the start of the captured packet bytes
 * @param[out] (ipv4) The address to IPv4 header. Nothing will be set if L3 protocol is IPv6.
 * @param[out] (ipv6) The address to IPv6 header. Nothing will be set if L3 protocol is IPv4.
 * @param[out] (proto) nyan
 * @return The offset to the L4 header
 */
u_int16_t ndff_set_iphdr(
        const struct pcap_pkthdr *header, const u_int16_t type, const u_char *packet,
        const u_int16_t offset, struct ndpi_iphdr **ipv4, struct ndpi_ipv6hdr **ipv6, u_int8_t *proto);

/**
 * @brief Search an L4 header in the packet, and set TCP/UDP headers and its payloaad.
 * @fn ndff_set_l4hdr
 * @param[in] (header) Pcap Packet Header (Contains captured bytes length and timestamp)
 * @param[in] (packet) Raw packet bytes captured by pcap
 * @param[in] (offset) The offset to L4 header from the start of the packet
 * @param[in] (iph) IPv4 header if L3 protocol is IPv4. NULL should be set if L3 is IPv6
 * @param[in] (iph6) IPv6 header if L4 protocol is IPv6. NULL should be set if L3 is IPv4
 * @param[in] (proto) nyan
 * @param[out] (tcph) A pointer to TCP header if L4 proto is TCP. NULL will be set otherwise.
 * @param[out] (udph) A pointer to UDP header if L4 proto is UDP. NULL will be set otherwise.
 * @param[out] (payload) A pointer to the L4 payload
 * @param[out] (payload_len) Length of the upper (i.e. >= L5) layer.
 * @note tcph->source, tcph->dest should be passed to ntohs.
 */
u_int16_t ndff_set_l4hdr(
        const struct pcap_pkthdr *header, const u_char *packet,
        const u_int16_t offset, struct ndpi_iphdr *iph, struct ndpi_ipv6hdr *iph6, u_int8_t proto,
        struct ndpi_tcphdr **tcph, struct ndpi_udphdr **udph, u_int8_t **payload, u_int16_t *payload_len
);

#endif /* _NDFF_H */
