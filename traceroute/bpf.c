#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include <poll.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "traceroute.h"

static struct bpf_object* obj = NULL;
static struct ring_buffer* ringbuf = NULL;
static int ringbuf_fd = -1;

/*
 * Note: struct probe_event is shared between BPF and userspace.
 * We keep it here but could move it to a shared header if more files needed it.
 */
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
    uint8_t is_reply; /* 1 for reply, 0 for sent probe */
};

int bpf_decode_event(void* data, size_t data_sz) {
    if (data_sz < sizeof(struct probe_event))
        return -EINVAL;

    struct probe_event* ev = data;
    probe* pb;

    /* Find probe by dport (seq) */
    pb = probe_by_seq(ev->dport);
    if (!pb)
        return 0;

    if (pb->done)
        return 0;

    if (!ev->is_reply) {
        /* Probe sent event */
        pb->send_time = ev->send_time_ns / 1e9;
        return 0;
    }

    /* Hop reply event */
    pb->send_time = ev->send_time_ns / 1e9;
    pb->recv_time = ev->recv_time_ns / 1e9;
    pb->recv_ttl = 0;

    if (ev->protocol == 17) {  // UDP
        sockaddr_any from = {{0}};
        from.sin.sin_family = AF_INET;  // Assuming IPv4 for now
        from.sin.sin_addr.s_addr = ev->saddr[0];
        memcpy(&pb->res, &from, sizeof(pb->res));
    }

    parse_icmp_res(pb, ev->icmp_type, ev->icmp_code, 0);
    probe_done(pb);

    return 0;
}

static int handle_event(void* ctx, void* data, size_t data_sz) {
    return bpf_decode_event(data, data_sz);
}

int bpf_init(const char* obj_path) {
    struct bpf_program* prog;
    struct bpf_map* events_map;

    if (!debug) {
        libbpf_set_print(NULL);
    }

    /* Check if we have enough privileges (CAP_BPF or root) */
    /* libbpf will fail later if we don't, but we can try to be proactive */

    obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        /* This might happen if obj_path is invalid or libbpf doesn't like it */
        return -1;
    }

    if (bpf_object__load(obj)) {
        /* This is where EPERM usually happens */
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }

    bpf_object__for_each_program(prog, obj) {
        if (bpf_program__attach(prog) == NULL) {
            /* Some programs might fail to attach if kprobes are not supported */
            continue;
        }
    }

    events_map = bpf_object__find_map_by_name(obj, "events");
    if (!events_map) {
        fprintf(stderr, "Failed to find 'events' map\n");
        return -1;
    }

    ringbuf_fd = bpf_map__fd(events_map);
    ringbuf = ring_buffer__new(ringbuf_fd, handle_event, NULL, NULL);
    if (!ringbuf) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return -1;
    }

    add_poll(ringbuf_fd, POLLIN);

    return 0;
}

void bpf_poll(int fd, int revents) {
    if (fd == ringbuf_fd) {
        ring_buffer__poll(ringbuf, 0);
    }
}

void bpf_print_histograms(void) {
    uint32_t hop;
    struct histogram {
        uint64_t buckets[64];
    } hist;
    struct bpf_map* hist_map;
    int fd;

    if (!obj)
        return;

    hist_map = bpf_object__find_map_by_name(obj, "hop_histograms");
    if (!hist_map)
        return;

    fd = bpf_map__fd(hist_map);

    printf("\nBPF Per-hop RTT Histograms (ms):\n");
    for (hop = 1; hop < 256; hop++) {
        if (bpf_map_lookup_elem(fd, &hop, &hist) == 0) {
            int found = 0;
            for (int i = 0; i < 64; i++) {
                if (hist.buckets[i] > 0)
                    found = 1;
            }
            if (found) {
                printf("  Hop %u: ", hop);
                for (int i = 0; i < 64; i++) {
                    if (hist.buckets[i] > 0) {
                        printf("%llu:%llu ", (unsigned long long)(1ULL << i), (unsigned long long)hist.buckets[i]);
                    }
                }
                printf("\n");
            }
        }
    }
}

void bpf_cleanup(void) {
    if (ringbuf)
        ring_buffer__free(ringbuf);
    if (obj)
        bpf_object__close(obj);
}