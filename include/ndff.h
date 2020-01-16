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
 * Detect upper layer protocol
 *
 * @par header = Pcap Packet Header
 * @par datalink_type = ...
 * @par eth_offset = offset
 * @par packet = raw packet bytes
 * @par type = detected type (out)
 * @par vlan_id = detected vlan id (out)
 * @par errbuf = Error Buffer
 * @return offset of the ip header
 */
u_int16_t ndff_detect_type(const struct pcap_pkthdr *header, const int datalink_type, const u_int16_t eth_offset, const u_char *packet, u_int16_t *type, u_int16_t *vlan_id, char **errbuf);

u_int16_t ndff_set_iphdr(const struct pcap_pkthdr *header, const u_int16_t type, const u_char *packet, const u_int16_t offset, struct ndpi_iphdr **ipv4, struct ndpi_ipv6hdr **ipv6, u_int8_t *proto);

#endif /* _NDFF_H */
