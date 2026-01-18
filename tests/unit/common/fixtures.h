#ifndef TEST_UNIT_COMMON_FIXTURES_H
#define TEST_UNIT_COMMON_FIXTURES_H

#include <stddef.h>

/**
 * decodes hex string into buffer
 * returns number of bytes decoded, or -1 on error
 */
int hex_decode(const char* hex, unsigned char* buf, size_t buf_len);

/* Byte blobs for common packet types */

/* IPv4+UDP probe packet (28 bytes) */
extern const char* FIXTURE_IPV4_UDP_PROBE;

/* IPv4 ICMP Time Exceeded quoting FIXTURE_IPV4_UDP_PROBE (36 bytes) */
extern const char* FIXTURE_IPV4_ICMP_TIME_EXCEEDED;

/* IPv6+UDP probe packet (48 bytes) */
extern const char* FIXTURE_IPV6_UDP_PROBE;

/* IPv6 ICMPv6 Time Exceeded quoting FIXTURE_IPV6_UDP_PROBE (56 bytes) */
extern const char* FIXTURE_IPV6_ICMPV6_TIME_EXCEEDED;

/* ICMP Dest Unreach (port unreachable) quoting UDP (36 bytes) */
extern const char* FIXTURE_IPV4_ICMP_DEST_UNREACH;

/* IPv4 ICMP Time Exceeded quoting TCP SYN probe (48 bytes) */
extern const char* FIXTURE_IPV4_ICMP_QUOTING_TCP;

#endif /* TEST_UNIT_COMMON_FIXTURES_H */