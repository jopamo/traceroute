#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_ICMP 1
#define IPPROTO_ICMPV6 58
#define ICMP_DEST_UNREACH 3
#define ICMP_TIME_EXCEEDED 11
#define ICMPV6_DEST_UNREACH 1
#define ICMPV6_TIME_EXCEED 3

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
};

struct iphdr {
    __u8 ihl : 4, version : 4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
};

struct ipv6hdr {
    __u8 priority : 4, version : 4;
    __u8 flow_lbl[3];
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    struct {
        __u8 u6_addr8[16];
    } saddr, daddr;
};

struct icmphdr {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    __be32 un;
};

struct icmp6hdr {
    __u8 icmp6_type;
    __u8 icmp6_code;
    __sum16 icmp6_cksum;
    __be32 icmp6_dataun;
};

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md* ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr* eth = data;

    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;
    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr* ip = (void*)(eth + 1);
        if ((void*)(ip + 1) > data_end)
            return XDP_PASS;

        if (ip->protocol == IPPROTO_ICMP) {
            struct icmphdr* icmp = (void*)((__u8*)ip + (ip->ihl * 4));
            if ((void*)(icmp + 1) > data_end)
                return XDP_PASS;

            if (icmp->type == ICMP_TIME_EXCEEDED || icmp->type == ICMP_DEST_UNREACH) {
                return bpf_redirect_map(&xsks, ctx->rx_queue_index, XDP_PASS);
            }
        }
    }
    else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr* ip6 = (void*)(eth + 1);
        if ((void*)(ip6 + 1) > data_end)
            return XDP_PASS;

        if (ip6->nexthdr == IPPROTO_ICMPV6) {
            struct icmp6hdr* icmp6 = (void*)(ip6 + 1);
            if ((void*)(icmp6 + 1) > data_end)
                return XDP_PASS;

            if (icmp6->icmp6_type == ICMPV6_TIME_EXCEED || icmp6->icmp6_type == ICMPV6_DEST_UNREACH) {
                return bpf_redirect_map(&xsks, ctx->rx_queue_index, XDP_PASS);
            }
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";