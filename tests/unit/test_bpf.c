#include "common/assert.h"
#include "common/mocks.h"
#include "traceroute.h"
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <stdlib.h>

/* Use common mocks */

/* The struct from bpf.c (we have to redefine it here or move it to a header) */
struct probe_event {
    uint32_t saddr[4];
    uint32_t daddr[4];
    uint16_t sport;
    uint16_t dport;
    uint8_t protocol;
    uint8_t ttl;
    uint64_t send_time_ns;
    uint64_t recv_time_ns;
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint32_t ifindex;
    uint8_t is_reply;
};

void test_bpf_event_decode_probe_sent(void) {
    probes = calloc(10, sizeof(probe));
    memset(&probes[0], 0, sizeof(probe));
    probes[0].seq = 33434;

    struct probe_event ev = {0};
    ev.dport = 33434;
    ev.send_time_ns = 1000000000ULL;  // 1s
    ev.is_reply = 0;

    ASSERT_OK(bpf_decode_event(&ev, sizeof(ev)));
    ASSERT_EQ_INT((int)probes[0].send_time, 1);
    ASSERT_EQ_INT(probes[0].done, 0);
    free(probes);
    probes = NULL;
}

void test_bpf_event_decode_hop_reply(void) {
    probes = calloc(10, sizeof(probe));
    memset(&probes[0], 0, sizeof(probe));
    probes[0].seq = 33435;

    struct probe_event ev = {0};
    ev.dport = 33435;
    ev.protocol = 17;  // UDP
    ev.saddr[0] = inet_addr("1.2.3.4");
    ev.send_time_ns = 2000000000ULL;  // 2s
    ev.recv_time_ns = 2500000000ULL;  // 2.5s
    ev.icmp_type = ICMP_TIME_EXCEEDED;
    ev.icmp_code = 0;
    ev.is_reply = 1;

    ASSERT_OK(bpf_decode_event(&ev, sizeof(ev)));
    ASSERT_EQ_INT((int)probes[0].send_time, 2);
    ASSERT_EQ_INT((int)(probes[0].recv_time * 10), 25);
    ASSERT_EQ_INT(probes[0].done, 1);
    ASSERT_EQ_INT(probes[0].res.sin.sin_addr.s_addr, inet_addr("1.2.3.4"));
    free(probes);
    probes = NULL;
}

void test_bpf_event_decode_bounds_checks(void) {
    char small_buf[10];
    ASSERT_ERR_CODE(bpf_decode_event(small_buf, sizeof(small_buf)), EINVAL);
}

void register_test_bpf(void) {
    test_bpf_event_decode_probe_sent();
    test_bpf_event_decode_hop_reply();
    test_bpf_event_decode_bounds_checks();
}
