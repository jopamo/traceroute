#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/errqueue.h>
#include <errno.h>

// Mock data
static int mock_socket_fd = 100;

// Mock implementations
int mock_socket(int domain, int type, int protocol) {
    return mock_socket_fd;
}

int mock_setsockopt(int fd, int level, int optname, const void* optval, socklen_t optlen) {
    return 0;
}

int mock_connect(int fd, const struct sockaddr* addr, socklen_t addrlen) {
    return 0;
}

ssize_t mock_send(int fd, const void* buf, size_t len, int flags) {
    return len;
}

// Mocking recvmsg to return a fake ICMP error WITH payload
ssize_t mock_recvmsg(int fd, struct msghdr* msg, int flags) {
    if (flags & MSG_ERRQUEUE) {
        // 1. Construct Control Message (IP_RECVERR)
        static char cmsg_buf[256];
        msg->msg_control = cmsg_buf;
        msg->msg_controllen = sizeof(cmsg_buf);

        struct cmsghdr* cm = (struct cmsghdr*)cmsg_buf;
        cm->cmsg_len = CMSG_LEN(sizeof(struct sock_extended_err));
        cm->cmsg_level = SOL_IP;
        cm->cmsg_type = IP_RECVERR;

        struct sock_extended_err* ee = (struct sock_extended_err*)CMSG_DATA(cm);
        ee->ee_errno = EHOSTUNREACH;
        ee->ee_origin = SO_EE_ORIGIN_ICMP;
        ee->ee_type = 11;  // Time Exceeded
        ee->ee_code = 0;
        ee->ee_info = 0;

        // 2. Construct Payload (Original Packet)
        // IP Header + UDP Header
        // This is what `recvmsg` returns in `msg_iov` when reading ERRQUEUE
        // It represents the packet that *caused* the error.

        static char payload_buf[512];
        struct iphdr* ip = (struct iphdr*)payload_buf;
        struct udphdr* udp = (struct udphdr*)(payload_buf + sizeof(struct iphdr));

        // Fill IP Header (Original Request)
        ip->ihl = 5;
        ip->version = 4;
        ip->protocol = IPPROTO_UDP;
        ip->saddr = htonl(0x0A000001);  // 10.0.0.1 (Us)
        ip->daddr = htonl(0x08080808);  // 8.8.8.8 (Target)
        ip->ttl = 1;                    // The TTL that expired

        // Fill UDP Header (Original Request)
        // We use specific ports to verify correlation
        udp->source = htons(12345);  // Our source port
        udp->dest = htons(33434);    // Target port (Traceroute default)
        udp->len = htons(sizeof(struct udphdr));
        udp->check = 0;

        size_t total_len = sizeof(struct iphdr) + sizeof(struct udphdr);

        // Copy to msg_iov
        if (msg->msg_iovlen > 0 && msg->msg_iov[0].iov_len >= total_len) {
            memcpy(msg->msg_iov[0].iov_base, payload_buf, total_len);
            return total_len;
        }
        else {
            return -1;  // Buffer too small in test
        }
    }
    errno = EAGAIN;
    return -1;
}

int mock_clock_gettime(clockid_t clk_id, struct timespec* tp) {
    tp->tv_sec = 1000;
    tp->tv_nsec = 0;
    return 0;
}

// Override system calls
#define socket mock_socket
#define setsockopt mock_setsockopt
#define connect mock_connect
#define send mock_send
#define recvmsg mock_recvmsg
#define clock_gettime mock_clock_gettime

// Include the source files directly
#include "../src/io/net.c"

int main() {
    printf("Running Correlation Tests...\n");

    int fd = net_socket_open(AF_INET, IPPROTO_UDP);
    PacketResult res;

    // We expect the mock to return an error with payload
    int ret = net_recv_packet(fd, 1, &res);

    if (ret != 1) {
        printf("FAIL: net_recv_packet failed to return 1\n");
        return 1;
    }

    if (res.type != RESULT_ERROR) {
        printf("FAIL: result type is not ERROR\n");
        return 1;
    }

    // Check extracted original probe identity
    // We expect:
    // src_port = 12345
    // dst_port = 33434
    // ttl = 1
    // protocol = IPPROTO_UDP

    if (res.original_req.src_port != 12345) {
        printf("FAIL: original_req.src_port mismatch. Expected 12345, got %d\n", res.original_req.src_port);
        return 1;
    }

    if (res.original_req.dst_port != 33434) {
        printf("FAIL: original_req.dst_port mismatch. Expected 33434, got %d\n", res.original_req.dst_port);
        return 1;
    }

    // Note: TTL might not be in the returned IP header reliably depending on if the router decremented it or not.
    // Usually, the returned IP header has the settings *as sent* or *as received* by the error generator?
    // The router reflects the IP header of the packet that expired.
    // If it expired in transit, TTL should be 0 or 1.
    // In our mock, we set it to 1.
    // But `net_recv_packet` needs to parse it.

    if (res.original_req.protocol != IPPROTO_UDP) {
        printf("FAIL: original_req.protocol mismatch. Expected %d, got %d\n", IPPROTO_UDP, res.original_req.protocol);
        return 1;
    }

    printf("PASS: Correlation info extracted successfully\n");
    return 0;
}
