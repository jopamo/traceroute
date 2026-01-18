#include "common/assert.h"
#include "common/fixtures.h"
#include "io/parse.h"
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

void test_parse_udp_header_valid(void) {
    unsigned char buf[16];
    memset(buf, 0, sizeof(buf));
    struct udphdr* udp = (struct udphdr*)buf;
    udp->source = htons(12345);
    udp->dest = htons(80);
    udp->len = htons(16);

    UDPPacket out;
    ASSERT_OK(parse_udp(buf, sizeof(buf), &out));
    ASSERT_EQ_INT(ntohs(out.hdr->source), 12345);
    ASSERT_EQ_U64(out.payload_len, 8);
}

void test_parse_udp_reject_short_buffer(void) {
    unsigned char buf[7];
    UDPPacket out;
    ASSERT_ERR_CODE(parse_udp(buf, sizeof(buf), &out), EINVAL);
}

void test_parse_tcp_header_min_valid(void) {
    unsigned char buf[20];
    memset(buf, 0, sizeof(buf));
    struct tcphdr* tcp = (struct tcphdr*)buf;
    tcp->source = htons(12345);
    tcp->dest = htons(80);
    tcp->doff = 5;  // 20 bytes

    TCPPacket out;
    ASSERT_OK(parse_tcp(buf, sizeof(buf), &out));
    ASSERT_EQ_INT(ntohs(out.hdr->source), 12345);
    ASSERT_EQ_U64(out.payload_len, 0);
}

void test_parse_tcp_reject_data_offset_short(void) {
    unsigned char buf[20];
    memset(buf, 0, sizeof(buf));
    struct tcphdr* tcp = (struct tcphdr*)buf;
    tcp->doff = 4;  // Invalid, min is 5

    TCPPacket out;
    ASSERT_ERR_CODE(parse_tcp(buf, sizeof(buf), &out), EINVAL);
}

void test_parse_tcp_reject_data_offset_past_buffer(void) {
    unsigned char buf[20];
    memset(buf, 0, sizeof(buf));
    struct tcphdr* tcp = (struct tcphdr*)buf;
    tcp->doff = 6;  // 24 bytes, but only 20 in buffer

    TCPPacket out;
    ASSERT_ERR_CODE(parse_tcp(buf, sizeof(buf), &out), EINVAL);
}

void register_test_parse_transport(void) {
    test_parse_udp_header_valid();
    test_parse_udp_reject_short_buffer();
    test_parse_tcp_header_min_valid();
    test_parse_tcp_reject_data_offset_short();
    test_parse_tcp_reject_data_offset_past_buffer();
}
