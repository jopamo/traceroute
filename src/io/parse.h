#ifndef TRACEROUTE_IO_PARSE_H
#define TRACEROUTE_IO_PARSE_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

typedef struct {
    const struct iphdr* hdr;
    const uint8_t* payload;
    size_t payload_len;
} IPv4Packet;

typedef struct {
    const struct ip6_hdr* hdr;
    const uint8_t* payload;
    size_t payload_len;
} IPv6Packet;

/**
 * Parses an IPv4 header from buf.
 * Returns 0 on success, negative error code on failure.
 */
int parse_ipv4(const uint8_t* buf, size_t len, IPv4Packet* out);

/**
 * Parses an IPv6 header from buf.
 * Returns 0 on success, negative error code on failure.
 */
int parse_ipv6(const uint8_t* buf, size_t len, IPv6Packet* out);

/**
 * Parses an IPv6 header and walks extension headers to find the upper-layer payload.
 * Returns 0 on success, negative error code on failure.
 */
int ipv6_find_payload(const uint8_t* buf,
                      size_t len,
                      uint8_t* proto_out,
                      const uint8_t** payload_out,
                      size_t* payload_len_out);

typedef struct {
    const struct udphdr* hdr;
    const uint8_t* payload;
    size_t payload_len;
} UDPPacket;

typedef struct {
    const struct tcphdr* hdr;
    const uint8_t* payload;
    size_t payload_len;
} TCPPacket;

typedef struct {
    const struct icmphdr* hdr;
    const uint8_t* payload;
    size_t payload_len;
} ICMPPacket;

typedef struct {
    const struct icmp6_hdr* hdr;
    const uint8_t* payload;
    size_t payload_len;
} ICMPv6Packet;

/**
 * Parses a UDP header from buf.
 * Returns 0 on success, negative error code on failure.
 */
int parse_udp(const uint8_t* buf, size_t len, UDPPacket* out);

/**
 * Parses a TCP header from buf.
 * Returns 0 on success, negative error code on failure.
 */
int parse_tcp(const uint8_t* buf, size_t len, TCPPacket* out);

/**
 * Parses an ICMP header from buf.
 * Returns 0 on success, negative error code on failure.
 */
int parse_icmp(const uint8_t* buf, size_t len, ICMPPacket* out);

/**
 * Parses an ICMPv6 header from buf.
 * Returns 0 on success, negative error code on failure.
 */
int parse_icmpv6(const uint8_t* buf, size_t len, ICMPv6Packet* out);

typedef struct {
    int is_ipv6;
    union {
        IPv4Packet ipv4;
        IPv6Packet ipv6;
    } ip;
    uint8_t transport_proto;
    union {
        UDPPacket udp;
        TCPPacket tcp;
    } transport;
} QuotedPacket;

/**
 * Parses an ICMP quote (the payload of an ICMP error message).
 * Returns 0 on success, negative error code on failure.
 */
int parse_icmp_quote(const uint8_t* buf, size_t len, int is_v6, QuotedPacket* out);

typedef struct {
    const struct sock_extended_err* ee;
    const struct sockaddr* offender;
    double timestamp;
} CMSGInfo;

/**
 * Parses control messages from recvmsg.
 * Returns 0 on success, negative error code on failure.
 */
int parse_cmsgs(struct msghdr* msg, CMSGInfo* out);

#endif /* TRACEROUTE_IO_PARSE_H */
