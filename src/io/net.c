#include "net.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/time.h>
#include <time.h>
#include <linux/types.h>
#include <linux/errqueue.h>

#ifndef IPV6_RECVERR
#define IPV6_RECVERR 25
#endif

#ifndef IPV6_UNICAST_HOPS
#define IPV6_UNICAST_HOPS 16
#endif

static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int net_socket_open(int family, int protocol) {
    int fd = socket(family, SOCK_DGRAM, protocol);
    if (fd < 0)
        return -1;

    // Set non-blocking
    struct timeval tv = {0, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return fd;
}

int net_configure_socket(int fd, int family, int ttl) {
    if (family == AF_INET) {
        if (setsockopt(fd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
            return -1;
    }
    else if (family == AF_INET6) {
        if (setsockopt(fd, SOL_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) < 0)
            return -1;
    }
    return 0;
}

int net_enable_recverr(int fd, int family) {
    int val = 1;
    if (family == AF_INET) {
        return setsockopt(fd, SOL_IP, IP_RECVERR, &val, sizeof(val));
    }
    else if (family == AF_INET6) {
        return setsockopt(fd, SOL_IPV6, IPV6_RECVERR, &val, sizeof(val));
    }
    return -1;
}

int net_send_probe(int fd, Probe* probe) {
    if (!probe)
        return -1;

    // For IP_RECVERR to work on UDP, we generally need to connect.
    // Re-connecting on UDP is allowed.
    if (connect(fd, &probe->dst_addr.sa, sizeof(sockaddr_any)) < 0) {
        return -1;
    }

    return send(fd, probe->payload, probe->payload_len, 0);
}

int net_recv_packet(int fd, int check_err_queue, PacketResult* result) {
    if (!result)
        return -1;
    memset(result, 0, sizeof(PacketResult));

    char buf[2048];
    char control[1024];
    struct msghdr msg;
    struct iovec iov;

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = &result->sender;
    msg.msg_namelen = sizeof(result->sender);
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    int flags = check_err_queue ? MSG_ERRQUEUE : 0;
    // Don't wait (MSG_DONTWAIT)
    flags |= MSG_DONTWAIT;

    int n = recvmsg(fd, &msg, flags);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        return -1;
    }

    result->recv_time = get_time_sec();

    // If we read from error queue, parse CMSG
    if (check_err_queue) {
        struct cmsghdr* cm;
        struct sock_extended_err* ee = NULL;

        for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
            if (cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_RECVERR) {
                ee = (struct sock_extended_err*)CMSG_DATA(cm);
            }
            else if (cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_RECVERR) {
                ee = (struct sock_extended_err*)CMSG_DATA(cm);
            }
            // Handle timestamp if available (not implemented yet in configure)
        }

        if (ee) {
            if (ee->ee_origin == SO_EE_ORIGIN_LOCAL) {
                result->type = RESULT_LOCAL_ERROR;
                result->error_no = ee->ee_errno;
            }
            else if (ee->ee_origin == SO_EE_ORIGIN_ICMP || ee->ee_origin == SO_EE_ORIGIN_ICMP6) {
                result->type = RESULT_ERROR;
                result->icmp_type = ee->ee_type;
                result->icmp_code = ee->ee_code;
                result->icmp_info = ee->ee_info;
                // The offender address is in SO_EE_OFFENDER(ee)
                // But recvmsg msg_name should also contain the offender?
                // "The msg_name member... contains the address of the network entity that caused the error"
                // So result->sender is already correct.
            }
        }
    }
    else {
        result->type = RESULT_OK;
        // Check for RecvTTL etc if needed
    }

    return 1;
}

int net_check_ipv6_support(void) {
    static int supported = -1;

    if (supported != -1) {
        return supported;
    }

    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        supported = 0;
    }
    else {
        close(fd);
        supported = 1;
    }

    return supported;
}
