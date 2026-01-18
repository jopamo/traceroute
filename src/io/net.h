#ifndef TRACEROUTE_IO_NET_H
#define TRACEROUTE_IO_NET_H

#include "../core/types.h"
#include <sys/types.h>

typedef enum {
    RESULT_NONE = 0,
    RESULT_OK,          // Normal reply
    RESULT_ERROR,       // ICMP Error (via ERRQUEUE)
    RESULT_LOCAL_ERROR  // Local error
} ResultType;

typedef struct {
    ResultType type;
    sockaddr_any sender;
    double recv_time;
    int recv_ttl;

    // For ICMP errors
    int icmp_type;
    int icmp_code;
    uint32_t icmp_info;

    // For local errors
    int error_no;
} PacketResult;

// Open a socket suitable for probing
int net_socket_open(int family, int protocol);

// Configure socket for traceroute (TTL, RecvErr, etc.)
int net_configure_socket(int fd, int family, int ttl);

// Enable IP_RECVERR
int net_enable_recverr(int fd, int family);

// Send the probe
int net_send_probe(int fd, Probe* probe);

// Receive a packet
// check_err_queue: 1 to read MSG_ERRQUEUE, 0 for normal
int net_recv_packet(int fd, int check_err_queue, PacketResult* result);

#endif  // TRACEROUTE_IO_NET_H