#ifndef _NDFF_H_
#define _NDFF_H_

#include <ndpi/ndpi_includes.h>
#include <ndpi/ndpi_typedefs.h>
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

#define IPPROTO_IPv6 41

/* TODO: Add Doxygen comments */
typedef struct ndff_flow
{
    u_int32_t flow_id;
    u_int32_t hash_value;
    u_int8_t protocol;

    u_int8_t ip_version;
    u_int16_t vlan_id;
    u_int32_t src_ip;
    u_int32_t dst_ip;
    u_int16_t src_port;
    u_int16_t dst_port;
	u_int32_t transaction_id;

    struct ndpi_in6_addr src_ipv6;
    struct ndpi_in6_addr dst_ipv6;

    char src_name[48], dst_name[48];

    u_int64_t first_seen, last_seen;
    u_int64_t out_bytes, in_bytes;
    u_int64_t out_packets, in_packets;

    ndpi_protocol detected_protocol;

    void *src_id, *dst_id;
    struct ndpi_flow_struct *ndpi_flow;
    u_int8_t is_detection_completed;

    char host_server_name[240];
    char bittorrent_hash[4];
	char info[160];

	struct
	{
			char client_requested_server_name[64], *server_names;
	} ssh_tls;
	struct
	{
			char url[256], user_agent[128];
	} http;
	struct
	{
			u_int16_t query_type, rsp_type;
			ndpi_ip_addr_t rsp_addr;
	} dns;
	struct
	{
		u_int8_t macaddr[6];
		u_int64_t lease_time;
		u_int32_t yiaddr;
	} dhcp;

} ndff_flow_t;

typedef void (*ndff_callback)(struct ndff_flow *flow, void*);

struct ndpi_proto ndff_get_protocol(
    struct ndpi_detection_module_struct *detect_mod, u_int8_t proto_num, u_int64_t time,
    struct ndpi_iphdr *iph, struct ndpi_ipv6hdr *iph6, u_int16_t ipsize,
    struct ndpi_id_struct *src, struct ndpi_id_struct *dst,
    ndff_callback on_detect, ndff_callback on_giveup,
    struct ndff_flow *flow);

/* TODO: write Doxygen comment */
struct ndff_flow *ndff_get_flow_info(
	void **trees,
	u_int32_t num_trees,
	u_int16_t vlan_id,
        u_int32_t rawsize,
        struct ndpi_id_struct **src, struct ndpi_id_struct **dst,
	struct ndpi_iphdr *iph, struct ndpi_ipv6hdr *iph6, /* L3. iph shall be NULL if L3 protocol is IPv6. */
	struct ndpi_tcphdr *tcph, struct ndpi_udphdr *udph /* L4. tcph shall be NULL if L4 protocol is TCP */
);

/* TODO: Add Doxygen comments */
int ndff_flow_node_cmp(const void *lhs, const void *rhs);

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
