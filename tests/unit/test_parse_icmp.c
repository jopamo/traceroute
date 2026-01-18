#include "common/assert.h"
#include "common/fixtures.h"
#include "io/parse.h"
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

void test_parse_icmp_time_exceeded(void) {
    unsigned char buf[8];
    memset(buf, 0, sizeof(buf));
    struct icmphdr* icmp = (struct icmphdr*)buf;
    icmp->type = ICMP_TIME_EXCEEDED;
    icmp->code = 0;

    ICMPPacket out;
    ASSERT_OK(parse_icmp(buf, sizeof(buf), &out));
    ASSERT_EQ_INT(out.hdr->type, ICMP_TIME_EXCEEDED);
}

void test_parse_icmp_dest_unreach(void) {
    unsigned char buf[8];
    memset(buf, 0, sizeof(buf));
    struct icmphdr* icmp = (struct icmphdr*)buf;
    icmp->type = ICMP_DEST_UNREACH;
    icmp->code = ICMP_PORT_UNREACH;

    ICMPPacket out;
    ASSERT_OK(parse_icmp(buf, sizeof(buf), &out));
    ASSERT_EQ_INT(out.hdr->type, ICMP_DEST_UNREACH);
    ASSERT_EQ_INT(out.hdr->code, ICMP_PORT_UNREACH);
}

void test_parse_icmp_echo_reply(void) {
    unsigned char buf[8];
    memset(buf, 0, sizeof(buf));
    struct icmphdr* icmp = (struct icmphdr*)buf;
    icmp->type = ICMP_ECHOREPLY;

    ICMPPacket out;
    ASSERT_OK(parse_icmp(buf, sizeof(buf), &out));
    ASSERT_EQ_INT(out.hdr->type, ICMP_ECHOREPLY);
}

void test_parse_icmpv6_time_exceeded(void) {
    unsigned char buf[8];
    memset(buf, 0, sizeof(buf));
    struct icmp6_hdr* icmp6 = (struct icmp6_hdr*)buf;
    icmp6->icmp6_type = ICMP6_TIME_EXCEEDED;
    icmp6->icmp6_code = 0;

    ICMPv6Packet out;
    ASSERT_OK(parse_icmpv6(buf, sizeof(buf), &out));
    ASSERT_EQ_INT(out.hdr->icmp6_type, ICMP6_TIME_EXCEEDED);
}

void test_parse_icmpv6_dest_unreach(void) {
    unsigned char buf[8];
    memset(buf, 0, sizeof(buf));
    struct icmp6_hdr* icmp6 = (struct icmp6_hdr*)buf;
    icmp6->icmp6_type = ICMP6_DST_UNREACH;
    icmp6->icmp6_code = ICMP6_DST_UNREACH_NOPORT;

    ICMPv6Packet out;
    ASSERT_OK(parse_icmpv6(buf, sizeof(buf), &out));
    ASSERT_EQ_INT(out.hdr->icmp6_type, ICMP6_DST_UNREACH);
}

void test_parse_icmp_reject_short_buffer(void) {
    unsigned char buf[7];
    ICMPPacket out;
    ASSERT_ERR_CODE(parse_icmp(buf, sizeof(buf), &out), EINVAL);
}

void test_parse_icmp_code_type_exposed(void) {
    unsigned char buf[8];
    memset(buf, 0, sizeof(buf));
    struct icmphdr* icmp = (struct icmphdr*)buf;
    icmp->type = 123;
    icmp->code = 45;

    ICMPPacket out;
    ASSERT_OK(parse_icmp(buf, sizeof(buf), &out));
    ASSERT_EQ_INT(out.hdr->type, 123);
    ASSERT_EQ_INT(out.hdr->code, 45);
}

void register_test_parse_icmp(void) {
    test_parse_icmp_time_exceeded();
    test_parse_icmp_dest_unreach();
    test_parse_icmp_echo_reply();
    test_parse_icmpv6_time_exceeded();
    test_parse_icmpv6_dest_unreach();
    test_parse_icmp_reject_short_buffer();
    test_parse_icmp_code_type_exposed();
}
