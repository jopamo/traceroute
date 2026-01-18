#include "json_writer.h"
#include <stdio.h>
#include <string.h>

int json_escape_string(char* out, size_t out_len, const char* in) {
    if (!in || !out || out_len == 0)
        return -1;

    char* curr = out;
    char* end = out + out_len - 1;  // Reserve space for null terminator

    *curr++ = '"';
    if (curr >= end)
        return -1;

    for (; *in; in++) {
        if (curr + 2 >= end)
            return -1;  // Check for safe space (worst case \uXXXX is 6 chars, standard escape is 2)

        switch (*in) {
            case '"':
                *curr++ = '\\';
                *curr++ = '"';
                break;
            case '\\':
                *curr++ = '\\';
                *curr++ = '\\';
                break;
            case '\b':
                *curr++ = '\\';
                *curr++ = 'b';
                break;
            case '\f':
                *curr++ = '\\';
                *curr++ = 'f';
                break;
            case '\n':
                *curr++ = '\\';
                *curr++ = 'n';
                break;
            case '\r':
                *curr++ = '\\';
                *curr++ = 'r';
                break;
            case '\t':
                *curr++ = '\\';
                *curr++ = 't';
                break;
            default:
                if ((unsigned char)*in < 32) {
                    if (curr + 6 >= end)
                        return -1;
                    curr += snprintf(curr, end - curr, "\\u%04x", (unsigned char)*in);
                }
                else {
                    *curr++ = *in;
                }
                break;
        }
    }

    if (curr >= end)
        return -1;
    *curr++ = '"';
    *curr = '\0';

    return curr - out;
}

int json_write_header(char* buf,
                      size_t len,
                      const char* dst_name,
                      const char* dst_addr,
                      unsigned int max_hops,
                      size_t packet_len) {
    char esc_name[256];
    char esc_addr[64];

    if (json_escape_string(esc_name, sizeof(esc_name), dst_name ? dst_name : "null") < 0)
        return -1;
    if (json_escape_string(esc_addr, sizeof(esc_addr), dst_addr ? dst_addr : "") < 0)
        return -1;

    return snprintf(
        buf, len,
        "{\"type\":\"header\", \"version\":1, \"dst_name\":%s, \"dst_addr\":%s, \"max_hops\":%u, \"packet_len\":%zu}",
        esc_name, esc_addr, max_hops, packet_len);
}

int json_write_probe(char* buf,
                     size_t len,
                     int ttl,
                     int probe_idx,
                     const char* addr_str,
                     double rtt_ms,
                     const char* err_str) {
    if (!buf || len == 0)
        return -1;

    char* curr = buf;
    char* end = buf + len;

    int n = snprintf(curr, end - curr, "{\"type\":\"probe\", \"ttl\":%d, \"probe\":%d", ttl, probe_idx);
    if (n < 0 || curr + n >= end)
        return -1;
    curr += n;

    if (addr_str) {
        char esc_addr[64];
        if (json_escape_string(esc_addr, sizeof(esc_addr), addr_str) < 0)
            return -1;
        n = snprintf(curr, end - curr, ", \"replied\":true, \"addr\":%s", esc_addr);
    }
    else {
        n = snprintf(curr, end - curr, ", \"replied\":false");
    }

    if (n < 0 || curr + n >= end)
        return -1;
    curr += n;

    if (rtt_ms >= 0) {
        n = snprintf(curr, end - curr, ", \"rtt_ms\":%.3f", rtt_ms);
        if (n < 0 || curr + n >= end)
            return -1;
        curr += n;
    }

    if (err_str && *err_str) {
        char esc_err[64];
        if (json_escape_string(esc_err, sizeof(esc_err), err_str) < 0)
            return -1;
        n = snprintf(curr, end - curr, ", \"err\":%s", esc_err);
        if (n < 0 || curr + n >= end)
            return -1;
        curr += n;
    }

    n = snprintf(curr, end - curr, "}");
    if (n < 0 || curr + n >= end)
        return -1;
    curr += n;

    return curr - buf;
}

int json_write_end(char* buf, size_t len) {
    return snprintf(buf, len, "{\"type\":\"end\"}");
}
