#include <linux/bpf.h>
#include <linux/types.h>

/* Define constants if headers are being difficult */
#define IPPROTO_ICMP 1
#define IPPROTO_UDP 17
#define ICMP_DEST_UNREACH 3
#define ICMP_TIME_EXCEEDED 11

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* Minimal pt_regs for x86_64 to satisfy BPF_KPROBE */
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long orig_rax;
    unsigned long rip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;
    unsigned long ss;
};

struct net;
struct sock;

/* Forward declarations for CO-RE */
struct sk_buff {
    unsigned char* data;
    __u16 network_header;
    __u16 transport_header;
    __u32 len;
} __attribute__((preserve_access_index));

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
} __attribute__((preserve_access_index));

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
} __attribute__((preserve_access_index));

struct icmphdr {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union {
        struct {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
        struct {
            __be16 __unused;
            __be16 mtu;
        } frag;
    } un;
} __attribute__((preserve_access_index));

struct probe_key {
    __u32 saddr[4];
    __u32 daddr[4];
    __u16 sport;
    __u16 dport;
    __u8 protocol;
};

struct probe_value {
    __u64 send_time_ns;
    __u8 ttl;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct probe_key);
    __type(value, struct probe_value);
} probes SEC(".maps");

struct probe_event {
    __u32 saddr[4];
    __u32 daddr[4];
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 ttl;
    __u64 send_time_ns;
    __u64 recv_time_ns;
    __u8 icmp_type;
    __u8 icmp_code;
    __u32 ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

#define NUM_BUCKETS 64
struct histogram {
    __u64 buckets[NUM_BUCKETS];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct histogram);
} hop_histograms SEC(".maps");

static __always_inline void fill_key_ipv4(struct probe_key* key,
                                          __u32 saddr,
                                          __u32 daddr,
                                          __u16 sport,
                                          __u16 dport,
                                          __u8 proto) {
    key->saddr[0] = saddr;
    key->saddr[1] = 0;
    key->saddr[2] = 0;
    key->saddr[3] = 0;
    key->daddr[0] = daddr;
    key->daddr[1] = 0;
    key->daddr[2] = 0;
    key->daddr[3] = 0;
    key->sport = sport;
    key->dport = dport;
    key->protocol = proto;
}

static __always_inline void update_histogram(__u32 ttl, __u64 rtt_ns) {
    __u32 hop = ttl;
    if (hop >= 256)
        return;

    struct histogram* hist = bpf_map_lookup_elem(&hop_histograms, &hop);
    if (!hist)
        return;

    // log2 bucket
    __u64 bucket = 0;
    __u64 val = rtt_ns / 1000000;  // ms
    if (val > 0) {
        bucket = 64 - __builtin_clzll(val);
        if (bucket >= NUM_BUCKETS)
            bucket = NUM_BUCKETS - 1;
    }

    __sync_fetch_and_add(&hist->buckets[bucket], 1);
}

SEC("kprobe/ip_output")
int BPF_KPROBE(handle_ip_output, struct net* net, struct sock* sk, struct sk_buff* skb) {
    unsigned char* data = BPF_CORE_READ(skb, data);
    struct iphdr ip;
    struct udphdr udp;

    if (bpf_probe_read_kernel(&ip, sizeof(ip), data) < 0)
        return 0;

    if (ip.protocol != IPPROTO_UDP)
        return 0;

    if (bpf_probe_read_kernel(&udp, sizeof(udp), data + (ip.ihl << 2)) < 0)
        return 0;

    struct probe_key key = {};
    fill_key_ipv4(&key, ip.saddr, ip.daddr, bpf_ntohs(udp.source), bpf_ntohs(udp.dest), IPPROTO_UDP);

    struct probe_value val = {};
    val.send_time_ns = bpf_ktime_get_ns();
    val.ttl = ip.ttl;

    bpf_map_update_elem(&probes, &key, &val, BPF_ANY);

    return 0;
}

SEC("kprobe/icmp_rcv")
int BPF_KPROBE(handle_icmp_rcv, struct sk_buff* skb) {
    unsigned char* data = BPF_CORE_READ(skb, data);
    struct iphdr ip;
    struct icmphdr icmp;

    if (bpf_probe_read_kernel(&ip, sizeof(ip), data) < 0)
        return 0;

    if (ip.protocol != IPPROTO_ICMP)
        return 0;

    if (bpf_probe_read_kernel(&icmp, sizeof(icmp), data + (ip.ihl << 2)) < 0)
        return 0;

    if (icmp.type != ICMP_TIME_EXCEEDED && icmp.type != ICMP_DEST_UNREACH)
        return 0;

    // Inner packet starts after ICMP header (8 bytes)
    struct iphdr inner_ip;
    if (bpf_probe_read_kernel(&inner_ip, sizeof(inner_ip), data + (ip.ihl << 2) + 8) < 0)
        return 0;

    if (inner_ip.protocol != IPPROTO_UDP)
        return 0;

    struct udphdr inner_udp;
    if (bpf_probe_read_kernel(&inner_udp, sizeof(inner_udp), data + (ip.ihl << 2) + 8 + (inner_ip.ihl << 2)) < 0)
        return 0;

    struct probe_key key = {};
    fill_key_ipv4(&key, inner_ip.saddr, inner_ip.daddr, bpf_ntohs(inner_udp.source), bpf_ntohs(inner_udp.dest),
                  IPPROTO_UDP);

    struct probe_value* val = bpf_map_lookup_elem(&probes, &key);
    if (!val)
        return 0;

    __u64 recv_time_ns = bpf_ktime_get_ns();
    __u64 rtt_ns = recv_time_ns - val->send_time_ns;

    update_histogram(val->ttl, rtt_ns);

    struct probe_event* ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->saddr[0] = ip.saddr;
    ev->daddr[0] = ip.daddr;
    ev->sport = bpf_ntohs(inner_udp.source);
    ev->dport = bpf_ntohs(inner_udp.dest);
    ev->protocol = IPPROTO_UDP;
    ev->ttl = val->ttl;
    ev->send_time_ns = val->send_time_ns;
    ev->recv_time_ns = recv_time_ns;
    ev->icmp_type = icmp.type;
    ev->icmp_code = icmp.code;

    bpf_ringbuf_submit(ev, 0);

    return 0;
}
