#include "common/assert.h"
#include "common/rng.h"
#include "io/parse.h"
#include <string.h>
#include <stdlib.h>

void prop_ipv6_ext_walk_never_overreads_random_buffers(void) {
    uint8_t buf[256];

    // Fuzz test
    for (int i = 0; i < 1000; i++) {
        size_t len = (test_rng_next() % 200) + 40;  // At least enough for IPv6 header

        for (size_t j = 0; j < len; j++) {
            buf[j] = (uint8_t)test_rng_next();
        }

        // Force version 6 to pass basic check
        buf[0] = (buf[0] & 0x0F) | 0x60;

        uint8_t proto;
        const uint8_t* payload;
        size_t payload_len;

        // Should not crash (ASAN will catch overreads)
        ipv6_find_payload(buf, len, &proto, &payload, &payload_len);
    }
}

void prop_icmp_quote_parser_never_overreads_random_buffers(void) {
    uint8_t buf[256];

    for (int i = 0; i < 1000; i++) {
        size_t len = (test_rng_next() % 200) + 20;

        for (size_t j = 0; j < len; j++) {
            buf[j] = (uint8_t)test_rng_next();
        }

        QuotedPacket out;
        int is_v6 = (i % 2);

        // If v4, ensure version 4
        if (!is_v6 && len >= 20) {
            buf[0] = (buf[0] & 0xF0) | 0x05;  // IHL 5
            buf[0] = (buf[0] & 0x0F) | 0x40;  // Version 4
        }
        // If v6, ensure version 6
        if (is_v6 && len >= 40) {
            buf[0] = (buf[0] & 0x0F) | 0x60;
        }

        parse_icmp_quote(buf, len, is_v6, &out);
    }
}

#include "core/json_writer.h"

void prop_json_encoder_roundtrip_basic(void) {
    // We don't have a parser, so "roundtrip" is hard.
    // Instead we fuzz the inputs to the encoder and ensure it produces
    // something that looks like JSON and doesn't crash.

    char buf[1024];
    char rand_str[100];

    for (int i = 0; i < 1000; i++) {
        size_t len = (test_rng_next() % 90) + 1;
        for (size_t j = 0; j < len; j++) {
            // Random ascii printable and non-printable
            rand_str[j] = (char)(test_rng_next() % 256);
        }
        rand_str[len] = '\0';

        // Fuzz write_header
        json_write_header(buf, sizeof(buf), rand_str, "1.1.1.1", 30, 60);
        if (buf[0] != '{') {
            fprintf(stderr, "JSON header didn't start with {: %s\n", buf);
            exit(1);
        }

        // Fuzz write_probe
        json_write_probe(buf, sizeof(buf), 1, 1, rand_str, 10.0, NULL);
        if (buf[0] != '{') {
            fprintf(stderr, "JSON probe didn't start with {: %s\n", buf);
            exit(1);
        }
    }
}

void register_test_property(void) {
    prop_ipv6_ext_walk_never_overreads_random_buffers();
    prop_icmp_quote_parser_never_overreads_random_buffers();
    prop_json_encoder_roundtrip_basic();
}
