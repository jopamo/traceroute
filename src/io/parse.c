#include "parse.h"
#include <errno.h>
#include <arpa/inet.h>

int parse_ipv4(const uint8_t* buf, size_t len, IPv4Packet* out) {
    if (len < sizeof(struct iphdr)) {
        return -EINVAL;
    }

    const struct iphdr* ip = (const struct iphdr*)buf;

    if (ip->version != 4) {
        return -EPROTONOSUPPORT;
    }

    if (ip->ihl < 5) {
        return -EINVAL;
    }

    size_t ihl_bytes = ip->ihl * 4;
    if (len < ihl_bytes) {
        return -EINVAL;
    }

    uint16_t total_len = ntohs(ip->tot_len);
    if (total_len < ihl_bytes) {
        return -EINVAL;
    }

    // Note: total_len might be larger than len if the packet was truncated by the kernel/pcap
    // but for our unit tests we want to ensure consistency.
    // However, in real traceroute, we might get truncated ICMP quotes.

    out->hdr = ip;
    out->payload = buf + ihl_bytes;

    if (total_len > len) {
        out->payload_len = len - ihl_bytes;
    }
    else {
        out->payload_len = total_len - ihl_bytes;
    }

    return 0;
}

int parse_ipv6(const uint8_t* buf, size_t len, IPv6Packet* out) {
    if (len < sizeof(struct ip6_hdr)) {
        return -EINVAL;
    }

    const struct ip6_hdr* ip6 = (const struct ip6_hdr*)buf;

    // The version field is in the first 4 bits of the first byte
    if ((ip6->ip6_vfc >> 4) != 6) {
        return -EPROTONOSUPPORT;
    }

    uint16_t payload_len = ntohs(ip6->ip6_plen);

    out->hdr = ip6;
    out->payload = buf + sizeof(struct ip6_hdr);

    if (payload_len > len - sizeof(struct ip6_hdr)) {
        out->payload_len = len - sizeof(struct ip6_hdr);
    }
    else {
        out->payload_len = payload_len;
    }

    return 0;
}

static int is_ipv6_extension_header(uint8_t next_header) {
    switch (next_header) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_FRAGMENT:
        case IPPROTO_DSTOPTS:
        case IPPROTO_AH:
            return 1;
        default:
            return 0;
    }
}

int ipv6_find_payload(const uint8_t* buf,
                      size_t len,
                      uint8_t* proto_out,
                      const uint8_t** payload_out,
                      size_t* payload_len_out) {
    IPv6Packet ip6_pkt;
    int rc = parse_ipv6(buf, len, &ip6_pkt);
    if (rc < 0)
        return rc;

    uint8_t next_proto = ip6_pkt.hdr->ip6_nxt;
    const uint8_t* ptr = ip6_pkt.payload;
    size_t remaining = ip6_pkt.payload_len;
    int headers_walked = 0;
    const int max_headers = 10;

    while (is_ipv6_extension_header(next_proto)) {
        if (headers_walked++ >= max_headers) {
            return -ELOOP;
        }

        if (remaining < 8) {
            return -EINVAL;
        }

        uint8_t ext_proto = ptr[0];
        size_t ext_len;

        if (next_proto == IPPROTO_FRAGMENT) {
            ext_len = 8;
        }
        else if (next_proto == IPPROTO_AH) {
            ext_len = (ptr[1] + 2) * 4;
        }
        else {
            ext_len = (ptr[1] + 1) * 8;
        }

        if (remaining < ext_len) {
            return -EINVAL;
        }

        next_proto = ext_proto;
        ptr += ext_len;
        remaining -= ext_len;
    }

    if (proto_out)
        *proto_out = next_proto;
    if (payload_out)
        *payload_out = ptr;
    if (payload_len_out)
        *payload_len_out = remaining;

    return 0;
}

int parse_udp(const uint8_t* buf, size_t len, UDPPacket* out) {
    if (len < sizeof(struct udphdr)) {
        return -EINVAL;
    }

    const struct udphdr* udp = (const struct udphdr*)buf;
    uint16_t udp_len = ntohs(udp->len);

    if (udp_len < sizeof(struct udphdr)) {
        return -EINVAL;
    }

    out->hdr = udp;
    out->payload = buf + sizeof(struct udphdr);

    if (udp_len > len) {
        out->payload_len = len - sizeof(struct udphdr);
    }
    else {
        out->payload_len = udp_len - sizeof(struct udphdr);
    }

    return 0;
}

int parse_tcp(const uint8_t* buf, size_t len, TCPPacket* out) {
    if (len < sizeof(struct tcphdr)) {
        return -EINVAL;
    }

    const struct tcphdr* tcp = (const struct tcphdr*)buf;
    size_t doff_bytes = tcp->doff * 4;

    if (doff_bytes < sizeof(struct tcphdr)) {
        return -EINVAL;
    }

    if (len < doff_bytes) {
        return -EINVAL;
    }

    out->hdr = tcp;
    out->payload = buf + doff_bytes;
    out->payload_len = len - doff_bytes;

    return 0;
}

int parse_icmp(const uint8_t* buf, size_t len, ICMPPacket* out) {
    if (len < sizeof(struct icmphdr)) {
        return -EINVAL;
    }

    const struct icmphdr* icmp = (const struct icmphdr*)buf;

    out->hdr = icmp;
    out->payload = buf + sizeof(struct icmphdr);
    out->payload_len = len - sizeof(struct icmphdr);

    return 0;
}

int parse_icmpv6(const uint8_t* buf, size_t len, ICMPv6Packet* out) {
    if (len < sizeof(struct icmp6_hdr)) {
        return -EINVAL;
    }

    const struct icmp6_hdr* icmp6 = (const struct icmp6_hdr*)buf;

    out->hdr = icmp6;
    out->payload = buf + sizeof(struct icmp6_hdr);
    out->payload_len = len - sizeof(struct icmp6_hdr);

    return 0;
}

int parse_icmp_quote(const uint8_t* buf, size_t len, int is_v6, QuotedPacket* out) {
    if (!buf || !out)
        return -EINVAL;
    memset(out, 0, sizeof(QuotedPacket));
    out->is_ipv6 = is_v6;

    int rc;
    uint8_t proto;
    const uint8_t* payload;
    size_t payload_len;

    if (!is_v6) {
        rc = parse_ipv4(buf, len, &out->ip.ipv4);
        if (rc < 0)
            return rc;
        proto = out->ip.ipv4.hdr->protocol;
        payload = out->ip.ipv4.payload;
        payload_len = out->ip.ipv4.payload_len;
    }
    else {
        rc = ipv6_find_payload(buf, len, &proto, &payload, &payload_len);
        if (rc < 0)
            return rc;
        // We also need the basic IPv6 header in out->ip.ipv6
        rc = parse_ipv6(buf, len, &out->ip.ipv6);
        if (rc < 0)
            return rc;
    }

    out->transport_proto = proto;
    if (proto == IPPROTO_UDP) {
        return parse_udp(payload, payload_len, &out->transport.udp);
    }
    else if (proto == IPPROTO_TCP) {
        return parse_tcp(payload, payload_len, &out->transport.tcp);
    }

    return 0;  // Unknown transport, but IP parsed
}

#include <sys/socket.h>
#include <linux/errqueue.h>
#include <time.h>

int parse_cmsgs(struct msghdr* msg, CMSGInfo* out) {
    if (!msg || !out)
        return -EINVAL;
    memset(out, 0, sizeof(CMSGInfo));

    struct cmsghdr* cm;
    for (cm = CMSG_FIRSTHDR(msg); cm; cm = CMSG_NXTHDR(msg, cm)) {
        void* ptr = CMSG_DATA(cm);

        if ((cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_RECVERR) ||
            (cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_RECVERR)) {
            if (cm->cmsg_len < CMSG_LEN(sizeof(struct sock_extended_err))) {
                return -EBADMSG;
            }
            out->ee = (const struct sock_extended_err*)ptr;
            out->offender = SO_EE_OFFENDER(out->ee);
        }
        else if (cm->cmsg_level == SOL_SOCKET) {
            if (cm->cmsg_type == SCM_TIMESTAMPNS) {
                struct timespec* ts = (struct timespec*)ptr;
                out->timestamp = ts->tv_sec + ts->tv_nsec / 1e9;
            }
            else if (cm->cmsg_type == SO_TIMESTAMP) {
                struct timeval* tv = (struct timeval*)ptr;
                out->timestamp = tv->tv_sec + tv->tv_usec / 1e6;
            }
            else if (cm->cmsg_type == SCM_TIMESTAMPING) {
                struct timespec* ts = (struct timespec*)ptr;
                // ts[0] is software, ts[1] is transformed hardware, ts[2] is raw hardware
                if (ts[2].tv_sec || ts[2].tv_nsec) {
                    out->timestamp = ts[2].tv_sec + ts[2].tv_nsec / 1e9;
                }
                else if (ts[0].tv_sec || ts[0].tv_nsec) {
                    out->timestamp = ts[0].tv_sec + ts[0].tv_nsec / 1e9;
                }
            }
        }
    }

    return 0;
}
