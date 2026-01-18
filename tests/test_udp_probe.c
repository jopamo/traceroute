#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/errqueue.h>
#include <errno.h>

// Mock data
static int mock_socket_fd = 100;
static int mock_connect_called = 0;
static int mock_send_called = 0;
static int mock_setsockopt_ttl_val = 0;
static int mock_recverr_enabled = 0;
static int mock_ipv6_supported = 1;

// Mock implementations
int mock_socket(int domain, int type, int protocol) {
    if (domain == AF_INET6 && !mock_ipv6_supported) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    return mock_socket_fd;
}

int mock_setsockopt(int fd, int level, int optname, const void* optval, socklen_t optlen) {
    if (level == SOL_IP && optname == IP_TTL) {
        mock_setsockopt_ttl_val = *(int*)optval;
    }
    if (level == SOL_IP && optname == IP_RECVERR) {
        mock_recverr_enabled = *(int*)optval;
    }
    return 0;
}

int mock_connect(int fd, const struct sockaddr* addr, socklen_t addrlen) {
    mock_connect_called++;
    return 0;
}

ssize_t mock_send(int fd, const void* buf, size_t len, int flags) {
    mock_send_called++;
    return len;
}

// Mocking recvmsg to return a fake ICMP error
ssize_t mock_recvmsg(int fd, struct msghdr* msg, int flags) {
    if (flags & MSG_ERRQUEUE) {
        // Construct a fake IP_RECVERR
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

        return 1;  // Success
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
#include "../src/probe/udp.c"

int main() {
    printf("Running P0.1 UDP Probe Tests...\n");

    // Test 1: UDP Probe Init
    Probe p;
    sockaddr_any dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin.sin_family = AF_INET;
    dst.sin.sin_addr.s_addr = 0x0100007f;  // 127.0.0.1

    if (udp_probe_init(&p, &dst, 1000, 33434, 1, 40) != 0) {
        printf("FAIL: udp_probe_init failed\n");
        return 1;
    }

    if (p.id.dst_port != 33434 || p.id.ttl != 1) {
        printf("FAIL: udp_probe_init bad values\n");
        return 1;
    }
    printf("PASS: udp_probe_init\n");

    // Test 2: Net Socket Open & Configure
    int fd = net_socket_open(AF_INET, IPPROTO_UDP);
    if (fd != mock_socket_fd) {
        printf("FAIL: net_socket_open\n");
        return 1;
    }

    net_configure_socket(fd, AF_INET, 64);
    if (mock_setsockopt_ttl_val != 64) {
        printf("FAIL: net_configure_socket TTL\n");
        return 1;
    }

    net_enable_recverr(fd, AF_INET);
    if (mock_recverr_enabled != 1) {
        printf("FAIL: net_enable_recverr\n");
        return 1;
    }
    printf("PASS: Socket configuration\n");

    // Test 3: Send Probe
    if (net_send_probe(fd, &p) < 0) {
        printf("FAIL: net_send_probe\n");
        return 1;
    }
    if (mock_connect_called != 1) {
        printf("FAIL: net_send_probe did not connect\n");
        return 1;
    }
    printf("PASS: Send Probe\n");

    // Test 4: Recv Error
    PacketResult res;
    // Check normal queue (should be empty/EAGAIN)
    if (net_recv_packet(fd, 0, &res) != 0) {
        printf("FAIL: net_recv_packet normal queue should be empty\n");
        return 1;
    }

    // Check error queue (mock returns ICMP Time Exceeded)
    if (net_recv_packet(fd, 1, &res) != 1) {
        printf("FAIL: net_recv_packet error queue failed\n");
        return 1;
    }

    if (res.type != RESULT_ERROR) {
        printf("FAIL: result type not ERROR\n");
        return 1;
    }
    if (res.icmp_type != 11) {
        printf("FAIL: wrong ICMP type %d\n", res.icmp_type);
        return 1;
    }
    printf("PASS: Recv Error\n");

    // Test 5: IPv6 Support Check
    mock_ipv6_supported = 1;
    if (net_check_ipv6_support() != 1) {
        printf("FAIL: net_check_ipv6_support should return 1\n");
        return 1;
    }
    printf("PASS: IPv6 Support Check\n");

    probe_cleanup(&p);
    return 0;
}
