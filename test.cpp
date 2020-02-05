#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <cstdlib>
extern "C" {
#include <ndpi/ndpi_typedefs.h>
#include <pcap.h>
#include <ndff.h>
}

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE 256
#endif

namespace {

class PcapFile
{
public:
    PcapFile(const char *filename)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        m_handle = pcap_open_offline(filename, errbuf);
    }

    const u_char *next(struct pcap_pkthdr &header)
    {
        return pcap_next(m_handle,  &header);
    }
    ~PcapFile()
    {
        pcap_close(m_handle);
    }
private:
    pcap_t *m_handle;
};


TEST(NdffTest, DetectVlanID) {
    const u_char *packet;
    struct pcap_pkthdr header;
    u_int16_t type, vlan_id, offset;
    char *errmsg = NULL;

    PcapFile pcap("./http_over_vlan.pcap");
    while (packet = pcap.next(header))
    {
        offset = ndff_detect_type(&header, DLT_EN10MB, 0, packet, &type, &vlan_id, &errmsg);
        EXPECT_EQ(ETH_PROTO_IPv4, type);
        EXPECT_EQ(18, offset);
    }
}

TEST(NdffTest, CorrectlyHandleIPv4Header) {
    const u_char *packet;
    struct pcap_pkthdr header;
    u_int16_t type, vlan_id, offset;
    char *errmsg = NULL;

    struct ndpi_iphdr *ipv4;
    struct ndpi_ipv6hdr *ipv6;
    u_int8_t proto;
    union {
        u_int32_t u32;
        u_int8_t u8[4];
    } ipaddr;

    PcapFile pcap("./google_ssl.pcap");
    packet = pcap.next(header);

    offset = ndff_detect_type(&header, DLT_EN10MB, 0, packet, &type, &vlan_id, &errmsg);
    offset = ndff_set_iphdr(&header, type, packet, offset, &ipv4, &ipv6, &proto);

    EXPECT_EQ(IPPROTO_TCP, proto);
    EXPECT_FALSE(ipv4 == NULL);
    EXPECT_EQ(NULL, ipv6);

    ipaddr.u32 = ipv4->saddr;
    EXPECT_EQ(172,ipaddr.u8[0]);
    EXPECT_EQ(31,ipaddr.u8[1]);
    EXPECT_EQ(3,ipaddr.u8[2]);
    EXPECT_EQ(224,ipaddr.u8[3]);

    ipaddr.u32 = ipv4->daddr;
    EXPECT_EQ(216,ipaddr.u8[0]);
    EXPECT_EQ(58,ipaddr.u8[1]);
    EXPECT_EQ(212,ipaddr.u8[2]);
    EXPECT_EQ(100,ipaddr.u8[3]);
}

TEST(NdffTest, CorrectlySetTCPHeader) {
    const u_char *packet;
    struct pcap_pkthdr header;
    u_int16_t type, vlan_id, offset;
    char *errmsg = NULL;

    struct ndpi_iphdr *ipv4;
    struct ndpi_ipv6hdr *ipv6;
    u_int8_t proto;
    union {
        u_int32_t u32;
        u_int8_t u8[4];
    } ipaddr;

    struct ndpi_tcphdr *tcph;
    struct ndpi_udphdr *udph;
    u_int16_t payload_len;
    u_int8_t *l4_payload;

    PcapFile pcap("./google_ssl.pcap");
    packet = pcap.next(header);

    offset = ndff_detect_type(&header, DLT_EN10MB, 0, packet, &type, &vlan_id, &errmsg);
    offset = ndff_set_iphdr(&header, type, packet, offset, &ipv4, &ipv6, &proto);
    offset = ndff_set_l4hdr(&header, packet, offset, ipv4, ipv6, proto, &tcph, &udph, &l4_payload, &payload_len);
    EXPECT_EQ(42835, ntohs(tcph->source));
    EXPECT_EQ(443, ntohs(tcph->dest));
}

TEST(NdffTest, CorrectlySetUDPHeader) {
    const u_char *packet;
    struct pcap_pkthdr header;
    u_int16_t type, vlan_id, offset;
    char *errmsg = NULL;

    struct ndpi_iphdr *ipv4;
    struct ndpi_ipv6hdr *ipv6;
    u_int8_t proto;
    union {
        u_int32_t u32;
        u_int8_t u8[4];
    } ipaddr;

    struct ndpi_tcphdr *tcph;
    struct ndpi_udphdr *udph;
    u_int16_t payload_len;
    u_int8_t *l4_payload;

    PcapFile pcap("./quic.pcap");
    packet = pcap.next(header);
    offset = ndff_detect_type(&header, DLT_EN10MB, 0, packet, &type, &vlan_id, &errmsg);
    offset = ndff_set_iphdr(&header, type, packet, offset, &ipv4, &ipv6, &proto);
    offset = ndff_set_l4hdr(&header, packet, offset, ipv4, ipv6, proto, &tcph, &udph, &l4_payload, &payload_len);
    EXPECT_EQ(57833, ntohs(udph->source));
    EXPECT_EQ(443, ntohs(udph->dest));
}

TEST(NdffTest, DetectType) {
    const u_char *packet;
    struct pcap_pkthdr header;
    u_int16_t type, vlan_id, offset;
    char *errmsg = NULL;

    PcapFile pcap("./google_ssl.pcap");

    while (packet = pcap.next(header))
    {
        offset = ndff_detect_type(&header, DLT_EN10MB, 0, packet, &type, &vlan_id, &errmsg);
        EXPECT_EQ(ETH_PROTO_IPv4, type);
        EXPECT_EQ(14, offset);
    }
}

TEST(NdffTest, GetFlowTest) {
    const u_char *packet;
    struct pcap_pkthdr header;
    u_int16_t type, vlan_id, offset;
    char *errmsg = NULL;

    struct ndpi_iphdr *ipv4;
    struct ndpi_ipv6hdr *ipv6;
    u_int8_t proto;
    union {
        u_int32_t u32;
        u_int8_t u8[4];
    } ipaddr;

    struct ndpi_tcphdr *tcph;
    struct ndpi_udphdr *udph;
    u_int16_t payload_len;
    u_int8_t *l4_payload;
    void **trees;
    trees = (void**) calloc(1, sizeof(void *));

    struct ndpi_id_struct *src, *dst;
    struct ndff_flow *flow;
    src = dst = NULL;

    PcapFile pcap("./google_ssl.pcap");

    // 172.31.3.224
    u_int32_t src_ip = (224 << 24) | (3<< 16) | (31 << 8) | 172;
    // 216.58.212.100
    u_int32_t dst_ip = (100 << 24) | (212<< 16) | (58 << 8) | 216;

    int cnt = 0;
    while (packet = pcap.next(header))
    {
        offset = ndff_detect_type(&header, DLT_EN10MB, 0, packet, &type, &vlan_id, &errmsg);
        offset = ndff_set_iphdr(&header, type, packet, offset, &ipv4, &ipv6, &proto);
        offset = ndff_set_l4hdr(&header, packet, offset, ipv4, ipv6, proto, &tcph, &udph, &l4_payload, &payload_len);
        flow = ndff_get_flow_info(trees,1,vlan_id, header.caplen, &src, &dst, ipv4, ipv6, tcph, udph);
        EXPECT_EQ(0, flow->flow_id);
        if (cnt++ == 4) break;
    }
    EXPECT_EQ(2, flow->in_packets);
    EXPECT_EQ(3, flow->out_packets);
    EXPECT_EQ(120, flow->in_bytes);
    EXPECT_EQ(292, flow->out_bytes);
    EXPECT_EQ(src_ip, flow->src_ip);
    EXPECT_EQ(dst_ip, flow->dst_ip);
}


}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
