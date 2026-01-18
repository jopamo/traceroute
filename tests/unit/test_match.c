#include "common/assert.h"
#include "correlate/match.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>

void test_match_extract_ipv4_udp(void) {
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));

    struct iphdr* ip = (struct iphdr*)buf;
    ip->version = 4;
    ip->ihl = 5;
    ip->protocol = IPPROTO_UDP;
    ip->ttl = 64;

    struct udphdr* udp = (struct udphdr*)(buf + 20);
    udp->source = htons(12345);
    udp->dest = htons(33434);

    ProbeIdentity id;
    ASSERT_EQ_INT(correlate_extract_id(buf, 28, &id), 1);
    ASSERT_EQ_INT(id.protocol, IPPROTO_UDP);
    ASSERT_EQ_INT(id.src_port, 12345);
    ASSERT_EQ_INT(id.dst_port, 33434);
    ASSERT_EQ_INT(id.ttl, 64);
}

void test_match_extract_ipv6_udp(void) {
    unsigned char buf[128];
    memset(buf, 0, sizeof(buf));

    struct ip6_hdr* ip6 = (struct ip6_hdr*)buf;
    ip6->ip6_vfc = 0x60;
    ip6->ip6_nxt = IPPROTO_UDP;
    ip6->ip6_hlim = 128;

    struct udphdr* udp = (struct udphdr*)(buf + 40);
    udp->source = htons(12345);
    udp->dest = htons(33434);

    ProbeIdentity id;
    ASSERT_EQ_INT(correlate_extract_id(buf, 48, &id), 1);
    ASSERT_EQ_INT(id.protocol, IPPROTO_UDP);
    ASSERT_EQ_INT(id.src_port, 12345);
    ASSERT_EQ_INT(id.dst_port, 33434);
    ASSERT_EQ_INT(id.ttl, 128);
}

void test_match_extract_tcp(void) {
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));

    struct iphdr* ip = (struct iphdr*)buf;
    ip->version = 4;
    ip->ihl = 5;
    ip->protocol = IPPROTO_TCP;

    struct tcphdr* tcp = (struct tcphdr*)(buf + 20);
    tcp->source = htons(12345);
    tcp->dest = htons(80);
    tcp->seq = htonl(1000);

    ProbeIdentity id;
    ASSERT_EQ_INT(correlate_extract_id(buf, 40, &id), 1);
    ASSERT_EQ_INT(id.protocol, IPPROTO_TCP);
    ASSERT_EQ_INT(id.sequence, 1000);
}

void test_match_correlate_logic(void) {
    PacketResult res = {0};
    res.original_req.protocol = IPPROTO_UDP;
    res.original_req.dst_port = 33434;
    res.original_req.src_port = 12345;

    Probe p = {0};
    p.id.protocol = IPPROTO_UDP;
    p.id.dst_port = 33434;
    p.id.src_port = 12345;

    ASSERT_EQ_INT(correlate_match(&res, &p), 1);

    p.id.dst_port = 33435;
    ASSERT_EQ_INT(correlate_match(&res, &p), 0);
}

void register_test_match(void) {
    test_match_extract_ipv4_udp();
    test_match_extract_ipv6_udp();
    test_match_extract_tcp();
    test_match_correlate_logic();
}
