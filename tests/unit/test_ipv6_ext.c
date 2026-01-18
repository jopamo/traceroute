#include "common/assert.h"
#include "common/fixtures.h"
#include "io/parse.h"
#include <netinet/ip6.h>
#include <arpa/inet.h>

void test_ipv6_ext_walk_none(void) {
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));
    struct ip6_hdr* ip6 = (struct ip6_hdr*)buf;
    ip6->ip6_vfc = 0x60;
    ip6->ip6_plen = htons(24);
    ip6->ip6_nxt = IPPROTO_UDP;

    uint8_t proto;
    const uint8_t* payload;
    size_t payload_len;
    ASSERT_OK(ipv6_find_payload(buf, 64, &proto, &payload, &payload_len));
    ASSERT_EQ_INT(proto, IPPROTO_UDP);
    ASSERT_EQ_U64(payload_len, 24);
    ASSERT_EQ_PTR(payload, buf + 40);
}

void test_ipv6_ext_walk_hop_by_hop(void) {
    unsigned char buf[128];
    memset(buf, 0, sizeof(buf));
    struct ip6_hdr* ip6 = (struct ip6_hdr*)buf;
    ip6->ip6_vfc = 0x60;
    ip6->ip6_plen = htons(40);
    ip6->ip6_nxt = IPPROTO_HOPOPTS;

    // Hop-by-hop header
    buf[40] = IPPROTO_UDP;  // Next header
    buf[41] = 0;            // Length (0 means 8 bytes)

    uint8_t proto;
    const uint8_t* payload;
    size_t payload_len;
    ASSERT_OK(ipv6_find_payload(buf, 128, &proto, &payload, &payload_len));
    ASSERT_EQ_INT(proto, IPPROTO_UDP);
    ASSERT_EQ_U64(payload_len, 32);
    ASSERT_EQ_PTR(payload, buf + 48);
}

void test_ipv6_ext_walk_routing(void) {
    unsigned char buf[128];
    memset(buf, 0, sizeof(buf));
    struct ip6_hdr* ip6 = (struct ip6_hdr*)buf;
    ip6->ip6_vfc = 0x60;
    ip6->ip6_plen = htons(40);
    ip6->ip6_nxt = IPPROTO_ROUTING;

    // Routing header
    buf[40] = IPPROTO_UDP;
    buf[41] = 1;  // Length (1 means 16 bytes)

    uint8_t proto;
    const uint8_t* payload;
    size_t payload_len;
    ASSERT_OK(ipv6_find_payload(buf, 128, &proto, &payload, &payload_len));
    ASSERT_EQ_INT(proto, IPPROTO_UDP);
    ASSERT_EQ_U64(payload_len, 24);
    ASSERT_EQ_PTR(payload, buf + 40 + 16);
}

void test_ipv6_ext_walk_fragment(void) {
    unsigned char buf[128];
    memset(buf, 0, sizeof(buf));
    struct ip6_hdr* ip6 = (struct ip6_hdr*)buf;
    ip6->ip6_vfc = 0x60;
    ip6->ip6_plen = htons(40);
    ip6->ip6_nxt = IPPROTO_FRAGMENT;

    // Fragment header (always 8 bytes)
    buf[40] = IPPROTO_UDP;

    uint8_t proto;
    const uint8_t* payload;
    size_t payload_len;
    ASSERT_OK(ipv6_find_payload(buf, 128, &proto, &payload, &payload_len));
    ASSERT_EQ_INT(proto, IPPROTO_UDP);
    ASSERT_EQ_U64(payload_len, 32);
    ASSERT_EQ_PTR(payload, buf + 48);
}

void test_ipv6_ext_walk_unknown_header_stops_safely(void) {
    unsigned char buf[128];
    memset(buf, 0, sizeof(buf));
    struct ip6_hdr* ip6 = (struct ip6_hdr*)buf;
    ip6->ip6_vfc = 0x60;
    ip6->ip6_plen = htons(40);
    ip6->ip6_nxt = 253;  // Use for testing (RFC 3692)

    uint8_t proto;
    ASSERT_OK(ipv6_find_payload(buf, 128, &proto, NULL, NULL));
    ASSERT_EQ_INT(proto, 253);
}

void test_ipv6_ext_walk_chain_too_long_guard(void) {
    unsigned char buf[256];
    memset(buf, 0, sizeof(buf));
    struct ip6_hdr* ip6 = (struct ip6_hdr*)buf;
    ip6->ip6_vfc = 0x60;
    ip6->ip6_plen = htons(200);
    ip6->ip6_nxt = IPPROTO_HOPOPTS;

    for (int i = 0; i < 15; i++) {
        buf[40 + i * 8] = IPPROTO_HOPOPTS;
        buf[40 + i * 8 + 1] = 0;
    }

    ASSERT_ERR_CODE(ipv6_find_payload(buf, 256, NULL, NULL, NULL), ELOOP);
}

void register_test_ipv6_ext(void) {
    test_ipv6_ext_walk_none();
    test_ipv6_ext_walk_hop_by_hop();
    test_ipv6_ext_walk_routing();
    test_ipv6_ext_walk_fragment();
    test_ipv6_ext_walk_unknown_header_stops_safely();
    test_ipv6_ext_walk_chain_too_long_guard();
}
