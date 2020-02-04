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

const std::vector<std::string> pcapFilePaths{
    "./google_ssl.pcap",
    "./http_over_vlan.pcap"
};

class NdffTest : public ::testing::Test {
protected:
    virtual void SetUp() {
        char errbuf[PCAP_ERRBUF_SIZE];
        for (const auto& filepath : pcapFilePaths)
        {
            pcap_t *handle = pcap_open_offline(filepath.c_str(), errbuf);
            if (handle == NULL)
            {
                fprintf(stderr, "Failed to open the pcap file: %s\n", errbuf);
                std::exit(1);
            }
            pcap_handles.push_back(handle);
        }
    }

    virtual void TearDown() {
        for (pcap_t *handle : pcap_handles)
        {
            pcap_close(handle);
        }
    }

    std::vector<pcap_t*> pcap_handles;
};

TEST_F(NdffTest, DetectVlanID) {
    const u_char *packet;
    struct pcap_pkthdr header;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline("./http_over_vlan.pcap", errbuf);

    u_int16_t type;
    u_int16_t vlan_id;
    u_int16_t ip_offset;
    char *errmsg = NULL;
    while ((packet = pcap_next(handle, &header)))
    {
        ip_offset = ndff_detect_type(&header, DLT_EN10MB, 0, packet, &type, &vlan_id, &errmsg);
        EXPECT_EQ(ETH_PROTO_IPv4, type);
        EXPECT_EQ(18, ip_offset);
    }
}

TEST_F(NdffTest, CorrectlyHandleIPv4Header) {
    const u_char *packet;
    struct pcap_pkthdr header;

    u_int16_t type;
    u_int16_t vlan_id;
    u_int16_t ip_offset, ip_payload_offset;
    char *errmsg = NULL;

    struct ndpi_iphdr *ipv4;
    struct ndpi_ipv6hdr *ipv6;
    u_int8_t proto;
    union {
        u_int32_t u32;
        u_int8_t u8[4];
    } ipaddr;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline("./google_ssl.pcap", errbuf);
    packet = pcap_next(handle, &header);
    ip_offset = ndff_detect_type(&header, DLT_EN10MB, 0, packet, &type, &vlan_id, &errmsg);
    ip_payload_offset = ndff_set_iphdr(&header, type, packet, ip_offset, &ipv4, &ipv6, &proto);
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

TEST_F(NdffTest, CorrectlySetTCPHeader) {
    const u_char *packet;
    struct pcap_pkthdr header;

    u_int16_t type;
    u_int16_t vlan_id;
    u_int16_t offset;
    char *errmsg = NULL;

    struct ndpi_iphdr *ipv4;
    struct ndpi_ipv6hdr *ipv6;
    u_int8_t proto;

    struct ndpi_tcphdr *tcph;
    struct ndpi_udphdr *udph;
    u_int16_t payload_len;
    u_int8_t *l4_payload;

    union {
        u_int32_t u32;
        u_int8_t u8[4];
    } ipaddr;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline("./google_ssl.pcap", errbuf);
    packet = pcap_next(handle, &header);
    offset = ndff_detect_type(&header, DLT_EN10MB, 0, packet, &type, &vlan_id, &errmsg);
    offset = ndff_set_iphdr(&header, type, packet, offset, &ipv4, &ipv6, &proto);
    offset = ndff_set_l4hdr(&header, packet, offset, ipv4, ipv6, proto, &tcph, &udph, &l4_payload, &payload_len);
    EXPECT_EQ(42835, ntohs(tcph->source));
    EXPECT_EQ(443, ntohs(tcph->dest));
}

TEST_F(NdffTest, CorrectlySetUDPHeader) {
    const u_char *packet;
    struct pcap_pkthdr header;

    u_int16_t type;
    u_int16_t vlan_id;
    u_int16_t offset;
    char *errmsg = NULL;

    struct ndpi_iphdr *ipv4;
    struct ndpi_ipv6hdr *ipv6;
    u_int8_t proto;

    struct ndpi_tcphdr *tcph;
    struct ndpi_udphdr *udph;
    u_int16_t payload_len;
    u_int8_t *l4_payload;

    union {
        u_int32_t u32;
        u_int8_t u8[4];
    } ipaddr;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline("./quic.pcap", errbuf);
    packet = pcap_next(handle, &header);
    offset = ndff_detect_type(&header, DLT_EN10MB, 0, packet, &type, &vlan_id, &errmsg);
    offset = ndff_set_iphdr(&header, type, packet, offset, &ipv4, &ipv6, &proto);
    offset = ndff_set_l4hdr(&header, packet, offset, ipv4, ipv6, proto, &tcph, &udph, &l4_payload, &payload_len);
    EXPECT_EQ(57833, ntohs(udph->source));
    EXPECT_EQ(443, ntohs(udph->dest));
}

TEST_F(NdffTest, DetectType) {
    const u_char *packet;
    struct pcap_pkthdr header;
    pcap_t *handle = pcap_handles[0];

    u_int16_t type;
    u_int16_t vlan_id;
    u_int16_t ip_offset;
    char *errmsg = NULL;
    while ((packet = pcap_next(handle, &header)))
    {
        ip_offset = ndff_detect_type(&header, DLT_EN10MB, 0, packet, &type, &vlan_id, &errmsg);
        EXPECT_EQ(ETH_PROTO_IPv4, type);
        EXPECT_EQ(14, ip_offset);
    }
}


}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
