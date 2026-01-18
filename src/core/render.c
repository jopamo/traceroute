#include "render.h"
#include <stdio.h>
#include <string.h>

static int append_str(char** curr, char* end, const char* str) {
    if (*curr >= end)
        return -1;
    int n = snprintf(*curr, end - *curr, "%s", str);
    if (n < 0 || *curr + n >= end)
        return -1;
    *curr += n;
    return 0;
}

int render_hop(char* buf, size_t len, int ttl, const RenderProbe* probes, int count, int show_ip) {
    if (!buf || len == 0 || !probes)
        return -1;

    char* curr = buf;
    char* end = buf + len;

    int n = snprintf(curr, end - curr, "%2d  ", ttl);
    if (n < 0 || curr + n >= end)
        return -1;
    curr += n;

    // Grouping logic:
    // Standard traceroute groups by address if subsequent probes are from same address.
    // "router (1.2.3.4)  1.234 ms  2.345 ms"
    // "router (1.2.3.4)  1.234 ms  other (5.6.7.8)  3.456 ms"

    const char* last_addr = NULL;
    const char* last_name = NULL;

    for (int i = 0; i < count; i++) {
        const RenderProbe* p = &probes[i];

        if (!p->replied) {
            if (i > 0)
                append_str(&curr, end, "  ");
            append_str(&curr, end, "*");
            last_addr = NULL;  // Reset grouping on timeout
            continue;
        }

        int same_as_last = 0;
        if (last_addr && p->addr && strcmp(last_addr, p->addr) == 0) {
            same_as_last = 1;
        }

        if (!same_as_last) {
            if (i > 0)
                append_str(&curr, end, "  ");

            const char* display_name = p->name ? p->name : p->addr;
            append_str(&curr, end, display_name);

            if (show_ip && p->name && p->addr) {
                if (curr + 2 + strlen(p->addr) >= end)
                    return -1;
                snprintf(curr, end - curr, " (%s)", p->addr);
                curr += strlen(curr);
            }
            else if (!p->name && !p->addr) {
                // Should not happen if replied is true
            }

            last_addr = p->addr;
            last_name = p->name;
        }

        if (curr + 16 >= end)
            return -1;
        snprintf(curr, end - curr, "  %.3f ms", p->rtt_ms);
        curr += strlen(curr);
    }

    return curr - buf;
}
