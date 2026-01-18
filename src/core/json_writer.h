#ifndef TRACEROUTE_CORE_JSON_WRITER_H
#define TRACEROUTE_CORE_JSON_WRITER_H

#include <stddef.h>
#include <stdint.h>
#include "../core/types.h"

// Returns number of bytes written (excluding null terminator), or negative on error
int json_write_header(char* buf,
                      size_t len,
                      const char* dst_name,
                      const char* dst_addr,
                      unsigned int max_hops,
                      size_t packet_len);
int json_write_probe(char* buf,
                     size_t len,
                     int ttl,
                     int probe_idx,
                     const Probe* pb,
                     double rtt_ms,
                     const char* err_str);
int json_write_end(char* buf, size_t len);

// Helper for escaping strings
int json_escape_string(char* out, size_t out_len, const char* in);

#endif /* TRACEROUTE_CORE_JSON_WRITER_H */
