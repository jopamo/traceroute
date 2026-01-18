#include "fixtures.h"
#include <ctype.h>
#include <string.h>

const char* FIXTURE_IPV4_UDP_PROBE = "4500001cabcd0000401100000a0000010a0000023039829a00080000";

const char* FIXTURE_IPV4_ICMP_TIME_EXCEEDED =
    "0b00f4ff000000004500001cabcd0000401100000a0000010a0000023039829a00080000";

const char* FIXTURE_IPV6_UDP_PROBE =
    "600000000008114000000000000000000000000000000001000000000000000000000000000000023039829a00080000";

const char* FIXTURE_IPV6_ICMPV6_TIME_EXCEEDED =
    "0300feff00000000600000000008114000000000000000000000000000000001000000000000000000000000000000023039829a00080000";

const char* FIXTURE_IPV4_ICMP_DEST_UNREACH = "0303fcfb000000004500001cabcd0000401100000a0000010a0000023039829a00080000";

const char* FIXTURE_IPV4_ICMP_QUOTING_TCP =
    "0b00f4ff0000000045000028abcd0000400600000a0000010a0000023039005000000001000000005002200000000000";

static int hex_val(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int hex_decode(const char* hex, unsigned char* buf, size_t buf_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0)
        return -1;
    size_t decoded_len = len / 2;
    if (decoded_len > buf_len)
        return -1;

    for (size_t i = 0; i < decoded_len; i++) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        buf[i] = (unsigned char)((hi << 4) | lo);
    }

    return (int)decoded_len;
}
