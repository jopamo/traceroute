#ifndef TRACEROUTE_CORE_TYPES_H
#define TRACEROUTE_CORE_TYPES_H

#include <netinet/in.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stddef.h>

typedef union {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
} sockaddr_any;

typedef struct {
    uint32_t flow_id;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t sequence;
    uint8_t ttl;
    uint8_t protocol;
    double timestamp_cookie;
} ProbeIdentity;

typedef struct {
    ProbeIdentity id;
    sockaddr_any dst_addr;
    sockaddr_any src_addr;
    void* payload;
    size_t payload_len;
} Probe;

#endif  // TRACEROUTE_CORE_TYPES_H
