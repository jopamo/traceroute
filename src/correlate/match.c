#include "match.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <string.h>
#include <arpa/inet.h>

#if defined(__GLIBC__)
#define UDPHDR_SPORT(UH) ((UH)->source)
#define UDPHDR_DPORT(UH) ((UH)->dest)
#define TCPHDR_SPORT(TH) ((TH)->source)
#define TCPHDR_DPORT(TH) ((TH)->dest)
#define TCPHDR_SEQ(TH) ((TH)->seq)
#else
#define UDPHDR_SPORT(UH) ((UH)->uh_sport)
#define UDPHDR_DPORT(UH) ((UH)->uh_dport)
#define TCPHDR_SPORT(TH) ((TH)->th_sport)
#define TCPHDR_DPORT(TH) ((TH)->th_dport)
#define TCPHDR_SEQ(TH) ((TH)->th_seq)
#endif

int correlate_extract_id(const void* buf, size_t len, ProbeIdentity* id) {
    if (!buf || len < sizeof(struct iphdr) || !id)
        return 0;

    memset(id, 0, sizeof(ProbeIdentity));

    const uint8_t* ptr = (const uint8_t*)buf;
    uint8_t version = (*ptr) >> 4;
    uint8_t proto = 0;
    const void* transport_header = NULL;
    size_t ip_header_len = 0;

    if (version == 4) {
        const struct iphdr* ip = (const struct iphdr*)buf;
        proto = ip->protocol;
        ip_header_len = ip->ihl * 4;
        if (len >= ip_header_len) {
            transport_header = ptr + ip_header_len;
            id->ttl = ip->ttl;
        }
    }
    else if (version == 6 && len >= sizeof(struct ip6_hdr)) {
        const struct ip6_hdr* ip6 = (const struct ip6_hdr*)buf;
        proto = ip6->ip6_nxt;
        ip_header_len = sizeof(struct ip6_hdr);
        // Basic IPv6 support - assuming no extension headers for MVP
        transport_header = ptr + ip_header_len;
        id->ttl = ip6->ip6_hlim;
    }

    if (!transport_header)
        return 0;

    id->protocol = proto;
    size_t remaining = len - ip_header_len;

    if (proto == IPPROTO_UDP && remaining >= sizeof(struct udphdr)) {
        const struct udphdr* udp = (const struct udphdr*)transport_header;
        id->src_port = ntohs(UDPHDR_SPORT(udp));
        id->dst_port = ntohs(UDPHDR_DPORT(udp));
        return 1;
    }
    else if (proto == IPPROTO_TCP && remaining >= sizeof(struct tcphdr)) {
        const struct tcphdr* tcp = (const struct tcphdr*)transport_header;
        id->src_port = ntohs(TCPHDR_SPORT(tcp));
        id->dst_port = ntohs(TCPHDR_DPORT(tcp));
        id->sequence = ntohl(TCPHDR_SEQ(tcp));
        return 1;
    }

    return 0;
}

int correlate_match(const PacketResult* res, const Probe* probe) {
    if (!res || !probe)
        return 0;

    // Basic matching: protocol, ports, and potentially sequence
    if (res->original_req.protocol != probe->id.protocol)
        return 0;

    if (res->original_req.dst_port != probe->id.dst_port)
        return 0;

    // If source port was fixed/known
    if (probe->id.src_port != 0 && res->original_req.src_port != probe->id.src_port)
        return 0;

    // Protocol specific extra checks
    if (res->original_req.protocol == IPPROTO_TCP) {
        if (res->original_req.sequence != probe->id.sequence)
            return 0;
    }

    return 1;
}
