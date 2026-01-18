#include "common/assert.h"
#include "common/fixtures.h"
#include "io/parse.h"
#include <netinet/ip.h>
#include <arpa/inet.h>

void test_parse_ipv4_valid_min_header(void) {
    unsigned char buf[20];
    memset(buf, 0, sizeof(buf));
    struct iphdr* ip = (struct iphdr*)buf;
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(20);
    ip->protocol = IPPROTO_UDP;

    IPv4Packet out;
    ASSERT_OK(parse_ipv4(buf, sizeof(buf), &out));
    ASSERT_EQ_INT(out.hdr->protocol, IPPROTO_UDP);
    ASSERT_EQ_U64(out.payload_len, 0);
}

void test_parse_ipv4_reject_ihl_too_small(void) {
    unsigned char buf[20];
    memset(buf, 0, sizeof(buf));
    struct iphdr* ip = (struct iphdr*)buf;
    ip->version = 4;
    ip->ihl = 4;  // Invalid, min is 5

    IPv4Packet out;
    ASSERT_ERR_CODE(parse_ipv4(buf, sizeof(buf), &out), EINVAL);
}

void test_parse_ipv4_reject_ihl_too_large_for_buffer(void) {
    unsigned char buf[20];
    memset(buf, 0, sizeof(buf));
    struct iphdr* ip = (struct iphdr*)buf;
    ip->version = 4;
    ip->ihl = 6;  // Requires 24 bytes

    IPv4Packet out;
    ASSERT_ERR_CODE(parse_ipv4(buf, sizeof(buf), &out), EINVAL);
}

void test_parse_ipv4_reject_total_len_smaller_than_header(void) {
    unsigned char buf[20];
    memset(buf, 0, sizeof(buf));
    struct iphdr* ip = (struct iphdr*)buf;
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(19);  // Invalid, smaller than IHL

    IPv4Packet out;
    ASSERT_ERR_CODE(parse_ipv4(buf, sizeof(buf), &out), EINVAL);
}

void test_parse_ipv4_accept_options_and_locate_payload(void) {
    unsigned char buf[24];
    memset(buf, 0, sizeof(buf));
    struct iphdr* ip = (struct iphdr*)buf;
    ip->version = 4;
    ip->ihl = 6;  // 24 bytes
    ip->tot_len = htons(24);
    buf[20] = 0xAA;  // First byte of options/payload

    IPv4Packet out;
    ASSERT_OK(parse_ipv4(buf, sizeof(buf), &out));
    ASSERT_EQ_U64(out.payload_len, 0);
    ASSERT_EQ_PTR(out.payload, buf + 24);
}

void test_parse_ipv4_fragment_flags_and_offsets_exposed(void) {
    unsigned char buf[20];
    memset(buf, 0, sizeof(buf));
    struct iphdr* ip = (struct iphdr*)buf;
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(20);
    ip->frag_off = htons(0x2000);  // More fragments flag

    IPv4Packet out;
    ASSERT_OK(parse_ipv4(buf, sizeof(buf), &out));
    ASSERT_EQ_INT(ntohs(out.hdr->frag_off), 0x2000);
}

void register_test_parse_ipv4(void) {
    test_parse_ipv4_valid_min_header();
    test_parse_ipv4_reject_ihl_too_small();
    test_parse_ipv4_reject_ihl_too_large_for_buffer();
    test_parse_ipv4_reject_total_len_smaller_than_header();
    test_parse_ipv4_accept_options_and_locate_payload();
    test_parse_ipv4_fragment_flags_and_offsets_exposed();
}
