#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <poll.h>
#include <net/if.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "traceroute.h"

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define UMEM_SIZE (NUM_FRAMES * FRAME_SIZE)

struct xsk_socket_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;
    struct xsk_umem* umem;
    void* buffer;
    struct xsk_socket* xsk;
};

static struct xsk_socket_info* xsk_info = NULL;
static struct xdp_program* xdp_prog = NULL;

static struct xsk_socket_info* xsk_configure_umem(void) {
    struct xsk_socket_info* info;
    void* packet_buffer;
    int ret;

    info = calloc(1, sizeof(*info));
    if (!info)
        return NULL;

    ret = posix_memalign(&packet_buffer, getpagesize(), UMEM_SIZE);
    if (ret)
        return NULL;

    ret = xsk_umem__create(&info->umem, packet_buffer, UMEM_SIZE, &info->fq, &info->cq, NULL);
    if (ret)
        return NULL;

    info->buffer = packet_buffer;
    return info;
}

int xdp_init(const char* ifname, const char* obj_path) {
    const char* xdp_objs[] = {obj_path, "xdp_probe.bpf.o", "bpf/xdp_probe.bpf.o",
                              "/usr/share/traceroute/xdp_probe.bpf.o", NULL};
    int i;
    const char* found_path = NULL;

    for (i = 0; xdp_objs[i]; i++) {
        if (access(xdp_objs[i], R_OK) == 0) {
            found_path = xdp_objs[i];
            break;
        }
    }

    if (!found_path)
        return -1;

    int ifindex = if_nametoindex(ifname);
    if (!ifindex)
        return -1;

    struct bpf_object* bpf_obj = bpf_object__open_file(found_path, NULL);
    if (!bpf_obj)
        return -1;

    if (bpf_object__load(bpf_obj))
        return -1;

    struct bpf_program* bpf_prog = bpf_object__find_program_by_name(bpf_obj, "xdp_prog");
    if (!bpf_prog)
        return -1;

    xdp_prog = xdp_program__from_bpf_obj(bpf_obj, "xdp_prog");
    if (!xdp_prog)
        return -1;

    if (xdp_program__attach(xdp_prog, ifindex, XDP_MODE_NATIVE, 0) < 0) {
        if (xdp_program__attach(xdp_prog, ifindex, XDP_MODE_SKB, 0) < 0) {
            return -1;
        }
    }

    xsk_info = xsk_configure_umem();
    if (!xsk_info)
        return -1;

    struct xsk_socket_config xsk_cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
        .bind_flags = XDP_USE_NEED_WAKEUP,
    };

    int ret = xsk_socket__create(&xsk_info->xsk, ifname, 0, xsk_info->umem, &xsk_info->rx, &xsk_info->tx, &xsk_cfg);
    if (ret)
        return -1;

    // We also need to add the XSK to the XSKMAP in the BPF program
    int xsk_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "xsks");
    if (xsk_map_fd < 0)
        return -1;

    int key = 0;  // rx_queue_index, simplified
    int fd = xsk_socket__fd(xsk_info->xsk);
    ret = bpf_map_update_elem(xsk_map_fd, &key, &fd, 0);
    if (ret)
        return -1;

    add_poll(fd, POLLIN);

    return 0;
}

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>

void xdp_poll(int fd, int revents) {
    if (!xsk_info || fd != xsk_socket__fd(xsk_info->xsk))
        return;

    uint32_t idx_rx, idx_fq;
    unsigned int rcvd = xsk_ring_cons__peek(&xsk_info->rx, 16, &idx_rx);
    if (!rcvd)
        return;

    uint32_t ret = xsk_ring_prod__reserve(&xsk_info->fq, rcvd, &idx_fq);
    while (ret != rcvd) {
        ret = xsk_ring_prod__reserve(&xsk_info->fq, rcvd, &idx_fq);
    }

    for (unsigned int i = 0; i < rcvd; i++) {
        const struct xdp_desc* desc = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx + i);
        uint64_t addr = desc->addr;
        uint32_t len = desc->len;
        uint8_t* pkt = xsk_umem__get_data(xsk_info->buffer, addr);

        if (len > sizeof(struct ethhdr)) {
            struct ethhdr* eth = (struct ethhdr*)pkt;
            uint8_t* payload = pkt + sizeof(struct ethhdr);
            uint32_t paylen = len - sizeof(struct ethhdr);

            if (eth->h_proto == htons(ETH_P_IP) && paylen >= sizeof(struct iphdr)) {
                struct iphdr* ip = (struct iphdr*)payload;
                if (ip->protocol == IPPROTO_ICMP) {
                    struct icmphdr* icmp = (struct icmphdr*)(payload + (ip->ihl * 4));
                    if (icmp->type == ICMP_TIME_EXCEEDED || icmp->type == ICMP_DEST_UNREACH) {
                        // Original packet starts after ICMP header (8 bytes)
                        uint8_t* quoted = (uint8_t*)icmp + 8;
                        uint32_t quoted_len = paylen - (uintptr_t)((uint8_t*)quoted - payload);

                        // We'd need to find the probe and call parse_icmp_res
                        // But finding the probe from RAW data is what mod-udp does too.
                    }
                }
            }
        }

        *xsk_ring_prod__fill_addr(&xsk_info->fq, idx_fq + i) = addr;
    }

    xsk_ring_prod__submit(&xsk_info->fq, rcvd);
    xsk_ring_cons__release(&xsk_info->rx, rcvd);
}

void xdp_cleanup(void) {
    if (xsk_info) {
        if (xsk_info->xsk)
            xsk_socket__delete(xsk_info->xsk);
        if (xsk_info->umem)
            xsk_umem__delete(xsk_info->umem);
        free(xsk_info->buffer);
        free(xsk_info);
    }
}
