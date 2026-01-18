#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "traceroute.h"

static void json_escape(const char* s) {
    if (!s) {
        printf("null");
        return;
    }
    putchar('"');
    for (; *s; s++) {
        switch (*s) {
            case '"':
                printf("\\\"");
                break;
            case '\\':
                printf("\\\\");
                break;
            case '\b':
                printf("\\b");
                break;
            case '\f':
                printf("\\f");
                break;
            case '\n':
                printf("\\n");
                break;
            case '\r':
                printf("\\r");
                break;
            case '\t':
                printf("\\t");
                break;
            default:
                if ((unsigned char)*s < 32)
                    printf("\\u%04x", *s);
                else
                    putchar(*s);
                break;
        }
    }
    putchar('"');
}

void tr_export_jsonl_header(const char* dst_name,
                            const sockaddr_any* dst_addr,
                            unsigned int max_hops,
                            size_t packet_len) {
    printf("{\"type\":\"header\", \"version\":1, \"dst_name\":");
    json_escape(dst_name);
    printf(", \"dst_addr\":");
    json_escape(addr2str(dst_addr));
    printf(", \"max_hops\":%u, \"packet_len\":%zu}\n", max_hops, packet_len);
    fflush(stdout);
}

extern probe* probes;
extern unsigned int probes_per_hop;

void tr_export_jsonl_probe(probe* pb) {
    unsigned int idx = (pb - probes);
    unsigned int ttl = idx / probes_per_hop + 1;
    unsigned int probe_idx = idx % probes_per_hop + 1;

    printf("{\"type\":\"probe\", \"ttl\":%u, \"probe\":%u", ttl, probe_idx);

    if (pb->res.sa.sa_family) {
        printf(", \"replied\":true, \"addr\":");
        json_escape(addr2str(&pb->res));
    }
    else {
        printf(", \"replied\":false");
    }

    if (pb->recv_time) {
        double rtt = (pb->recv_time - pb->send_time) * 1000.0;
        printf(", \"rtt_ms\":%.3f", rtt);
    }

    if (pb->err_str[0]) {
        printf(", \"err\":");
        json_escape(pb->err_str);
    }

    if (pb->ext) {
        printf(", \"extensions\":");
        json_escape(pb->ext);
    }

    printf("}\n");
    fflush(stdout);
}

void tr_export_jsonl_end(void) {
    printf("{\"type\":\"end\"}\n");
    fflush(stdout);
}
