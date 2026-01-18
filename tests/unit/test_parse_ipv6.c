#include "common/assert.h"
#include "common/fixtures.h"
#include "io/parse.h"
#include <netinet/ip6.h>
#include <arpa/inet.h>

void test_parse_ipv6_valid_header(void) {
    unsigned char buf[40];
    memset(buf, 0, sizeof(buf));
    struct ip6_hdr* ip6 = (struct ip6_hdr*)buf;
    ip6->ip6_vfc = 0x60;  // Version 6
    ip6->ip6_plen = htons(0);
    ip6->ip6_nxt = IPPROTO_UDP;

    IPv6Packet out;
    ASSERT_OK(parse_ipv6(buf, sizeof(buf), &out));
    ASSERT_EQ_INT(out.hdr->ip6_nxt, IPPROTO_UDP);
    ASSERT_EQ_U64(out.payload_len, 0);
}

void test_parse_ipv6_reject_short_buffer(void) {
    unsigned char buf[39];
    memset(buf, 0, sizeof(buf));

    IPv6Packet out;
    ASSERT_ERR_CODE(parse_ipv6(buf, sizeof(buf), &out), EINVAL);
}

void test_parse_ipv6_payload_len_bounds(void) {
    unsigned char buf[50];
    memset(buf, 0, sizeof(buf));
    struct ip6_hdr* ip6 = (struct ip6_hdr*)buf;
    ip6->ip6_vfc = 0x60;
    ip6->ip6_plen = htons(20);  // Payload len 20, but only 10 bytes left in buffer

    IPv6Packet out;
    ASSERT_OK(parse_ipv6(buf, 50, &out));
    ASSERT_EQ_U64(out.payload_len, 10);
}

void test_parse_ipv6_next_header_exposed(void) {
    unsigned char buf[40];
    memset(buf, 0, sizeof(buf));
    struct ip6_hdr* ip6 = (struct ip6_hdr*)buf;
    ip6->ip6_vfc = 0x60;
    ip6->ip6_nxt = IPPROTO_TCP;

    IPv6Packet out;
    ASSERT_OK(parse_ipv6(buf, sizeof(buf), &out));
    ASSERT_EQ_INT(out.hdr->ip6_nxt, IPPROTO_TCP);
}

void register_test_parse_ipv6(void) {
    test_parse_ipv6_valid_header();
    test_parse_ipv6_reject_short_buffer();
    test_parse_ipv6_payload_len_bounds();
    test_parse_ipv6_next_header_exposed();
}
