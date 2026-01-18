#include "common/assert.h"
#include "common/fixtures.h"
#include "io/parse.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

void test_icmp_quote_extract_ipv4_inner_ip_and_transport(void) {
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));

    // IPv4 header
    struct iphdr* ip = (struct iphdr*)buf;
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(28);
    ip->protocol = IPPROTO_UDP;

    // UDP header
    struct udphdr* udp = (struct udphdr*)(buf + 20);
    udp->source = htons(12345);
    udp->dest = htons(33434);
    udp->len = htons(8);

    QuotedPacket out;
    ASSERT_OK(parse_icmp_quote(buf, 28, 0, &out));
    ASSERT_EQ_INT(out.is_ipv6, 0);
    ASSERT_EQ_INT(out.ip.ipv4.hdr->protocol, IPPROTO_UDP);
    ASSERT_EQ_INT(out.transport_proto, IPPROTO_UDP);
    ASSERT_EQ_INT(ntohs(out.transport.udp.hdr->dest), 33434);
}

void test_icmp_quote_extract_ipv6_inner_ip_and_transport(void) {
    unsigned char buf[128];
    memset(buf, 0, sizeof(buf));

    // IPv6 header
    struct ip6_hdr* ip6 = (struct ip6_hdr*)buf;
    ip6->ip6_vfc = 0x60;
    ip6->ip6_plen = htons(8);
    ip6->ip6_nxt = IPPROTO_UDP;

    // UDP header
    struct udphdr* udp = (struct udphdr*)(buf + 40);
    udp->source = htons(12345);
    udp->dest = htons(33434);
    udp->len = htons(8);

    QuotedPacket out;
    ASSERT_OK(parse_icmp_quote(buf, 48, 1, &out));
    ASSERT_EQ_INT(out.is_ipv6, 1);
    ASSERT_EQ_INT(out.transport_proto, IPPROTO_UDP);
    ASSERT_EQ_INT(ntohs(out.transport.udp.hdr->dest), 33434);
}

void test_icmp_quote_reject_missing_inner_headers(void) {
    unsigned char buf[10];
    QuotedPacket out;
    ASSERT_ERR_CODE(parse_icmp_quote(buf, 10, 0, &out), EINVAL);
}

void test_icmp_quote_handles_ipv4_options_in_inner_packet(void) {
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));

    struct iphdr* ip = (struct iphdr*)buf;
    ip->version = 4;
    ip->ihl = 6;  // 24 bytes
    ip->tot_len = htons(32);
    ip->protocol = IPPROTO_UDP;

    struct udphdr* udp = (struct udphdr*)(buf + 24);
    udp->dest = htons(33434);
    udp->len = htons(8);

    QuotedPacket out;
    ASSERT_OK(parse_icmp_quote(buf, 32, 0, &out));
    ASSERT_EQ_INT(out.transport_proto, IPPROTO_UDP);
    ASSERT_EQ_INT(ntohs(out.transport.udp.hdr->dest), 33434);
}

void test_icmp_quote_handles_ipv6_ext_headers_in_inner_packet(void) {
    unsigned char buf[128];
    memset(buf, 0, sizeof(buf));

    struct ip6_hdr* ip6 = (struct ip6_hdr*)buf;
    ip6->ip6_vfc = 0x60;
    ip6->ip6_plen = htons(16);
    ip6->ip6_nxt = IPPROTO_HOPOPTS;

    buf[40] = IPPROTO_UDP;
    buf[41] = 0;

    struct udphdr* udp = (struct udphdr*)(buf + 48);
    udp->dest = htons(33434);
    udp->len = htons(8);

    QuotedPacket out;
    ASSERT_OK(parse_icmp_quote(buf, 56, 1, &out));
    ASSERT_EQ_INT(out.transport_proto, IPPROTO_UDP);
    ASSERT_EQ_INT(ntohs(out.transport.udp.hdr->dest), 33434);
}

void test_icmp_quote_fragment_inner_packet_behavior_defined(void) {
    unsigned char buf[128];
    memset(buf, 0, sizeof(buf));

    struct ip6_hdr* ip6 = (struct ip6_hdr*)buf;
    ip6->ip6_vfc = 0x60;
    ip6->ip6_plen = htons(16);
    ip6->ip6_nxt = IPPROTO_FRAGMENT;

    buf[40] = IPPROTO_UDP;
    // Fragment offset etc would be here

    struct udphdr* udp = (struct udphdr*)(buf + 48);
    udp->dest = htons(33434);
    udp->len = htons(8);

    QuotedPacket out;
    ASSERT_OK(parse_icmp_quote(buf, 56, 1, &out));
    ASSERT_EQ_INT(out.transport_proto, IPPROTO_UDP);
}

void test_icmp_quote_bounds_checks_no_overread(void) {
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));

    struct iphdr* ip = (struct iphdr*)buf;
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(28);
    ip->protocol = IPPROTO_UDP;

    // Only half of UDP header in buffer
    QuotedPacket out;
    ASSERT_ERR_CODE(parse_icmp_quote(buf, 24, 0, &out), EINVAL);
}

void test_icmp_quote_fixture_ipv4_time_exceeded(void) {
    unsigned char buf[128];
    int len = hex_decode(FIXTURE_IPV4_ICMP_TIME_EXCEEDED, buf, sizeof(buf));
    ASSERT_OK(len);

    ICMPPacket icmp;
    ASSERT_OK(parse_icmp(buf, len, &icmp));
    ASSERT_EQ_INT(icmp.hdr->type, ICMP_TIME_EXCEEDED);

    QuotedPacket quoted;
    ASSERT_OK(parse_icmp_quote(icmp.payload, icmp.payload_len, 0, &quoted));
    ASSERT_EQ_INT(quoted.is_ipv6, 0);
    ASSERT_EQ_INT(quoted.transport_proto, IPPROTO_UDP);
    ASSERT_EQ_INT(ntohs(quoted.transport.udp.hdr->dest), 33434);
}

void test_icmp_quote_fixture_ipv4_dest_unreach(void) {
    unsigned char buf[128];
    int len = hex_decode(FIXTURE_IPV4_ICMP_DEST_UNREACH, buf, sizeof(buf));
    ASSERT_OK(len);

    ICMPPacket icmp;
    ASSERT_OK(parse_icmp(buf, len, &icmp));
    ASSERT_EQ_INT(icmp.hdr->type, ICMP_DEST_UNREACH);
    ASSERT_EQ_INT(icmp.hdr->code, ICMP_PORT_UNREACH);

    QuotedPacket quoted;
    ASSERT_OK(parse_icmp_quote(icmp.payload, icmp.payload_len, 0, &quoted));
    ASSERT_EQ_INT(quoted.is_ipv6, 0);
    ASSERT_EQ_INT(quoted.transport_proto, IPPROTO_UDP);
    ASSERT_EQ_INT(ntohs(quoted.transport.udp.hdr->dest), 33434);
}

void test_icmp_quote_fixture_ipv6_time_exceeded(void) {
    unsigned char buf[128];
    int len = hex_decode(FIXTURE_IPV6_ICMPV6_TIME_EXCEEDED, buf, sizeof(buf));
    ASSERT_OK(len);

    ICMPv6Packet icmp6;
    ASSERT_OK(parse_icmpv6(buf, len, &icmp6));
    ASSERT_EQ_INT(icmp6.hdr->icmp6_type, ICMP6_TIME_EXCEEDED);

    QuotedPacket quoted;
    ASSERT_OK(parse_icmp_quote(icmp6.payload, icmp6.payload_len, 1, &quoted));
    ASSERT_EQ_INT(quoted.is_ipv6, 1);
    ASSERT_EQ_INT(quoted.transport_proto, IPPROTO_UDP);
    ASSERT_EQ_INT(ntohs(quoted.transport.udp.hdr->dest), 33434);
}

void test_icmp_quote_fixture_tcp(void) {
    unsigned char buf[128];
    int len = hex_decode(FIXTURE_IPV4_ICMP_QUOTING_TCP, buf, sizeof(buf));
    ASSERT_OK(len);

    ICMPPacket icmp;
    ASSERT_OK(parse_icmp(buf, len, &icmp));

    QuotedPacket quoted;
    ASSERT_OK(parse_icmp_quote(icmp.payload, icmp.payload_len, 0, &quoted));
    ASSERT_EQ_INT(quoted.is_ipv6, 0);
    ASSERT_EQ_INT(quoted.transport_proto, IPPROTO_TCP);
    ASSERT_EQ_INT(ntohs(quoted.transport.tcp.hdr->dest), 80);
}

void register_test_icmp_quote(void) {
    test_icmp_quote_extract_ipv4_inner_ip_and_transport();
    test_icmp_quote_extract_ipv6_inner_ip_and_transport();
    test_icmp_quote_reject_missing_inner_headers();
    test_icmp_quote_handles_ipv4_options_in_inner_packet();
    test_icmp_quote_handles_ipv6_ext_headers_in_inner_packet();
    test_icmp_quote_fragment_inner_packet_behavior_defined();
    test_icmp_quote_bounds_checks_no_overread();
    test_icmp_quote_fixture_ipv4_time_exceeded();
    test_icmp_quote_fixture_ipv4_dest_unreach();
    test_icmp_quote_fixture_ipv6_time_exceeded();
    test_icmp_quote_fixture_tcp();
}
