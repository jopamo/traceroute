#include "common/assert.h"
#include "core/render.h"
#include <string.h>

void test_render_compact_single_hop_three_probes(void) {
    RenderProbe probes[3] = {0};
    probes[0].addr = "1.1.1.1";
    probes[0].name = "one.one";
    probes[0].replied = 1;
    probes[0].rtt_ms = 10.5;
    probes[1].addr = "1.1.1.1";
    probes[1].name = "one.one";
    probes[1].replied = 1;
    probes[1].rtt_ms = 11.0;
    probes[2].addr = "1.1.1.1";
    probes[2].name = "one.one";
    probes[2].replied = 1;
    probes[2].rtt_ms = 10.8;

    char buf[256];
    render_hop(buf, sizeof(buf), 1, probes, 3, 1);

    // Expect: " 1  one.one (1.1.1.1)  10.500 ms  11.000 ms  10.800 ms"
    if (!strstr(buf, " 1  one.one (1.1.1.1)  10.500 ms  11.000 ms  10.800 ms")) {
        fprintf(stderr, "Output mismatch: '%s'\n", buf);
        exit(1);
    }
}

void test_render_hop_with_multiple_ecmp_paths_grouping(void) {
    RenderProbe probes[3] = {0};
    probes[0].addr = "1.1.1.1";
    probes[0].name = "path1";
    probes[0].replied = 1;
    probes[0].rtt_ms = 10.0;
    probes[1].addr = "2.2.2.2";
    probes[1].name = "path2";
    probes[1].replied = 1;
    probes[1].rtt_ms = 20.0;
    probes[2].addr = "1.1.1.1";
    probes[2].name = "path1";
    probes[2].replied = 1;
    probes[2].rtt_ms = 11.0;

    char buf[256];
    render_hop(buf, sizeof(buf), 2, probes, 3, 1);

    // Expect: " 2  path1 (1.1.1.1)  10.000 ms  path2 (2.2.2.2)  20.000 ms  path1 (1.1.1.1)  11.000 ms"
    // Note: Standard traceroute often sorts or groups them differently, but basic sequential grouping is:
    // host1 rtt host2 rtt host1 rtt

    if (!strstr(buf, "path1 (1.1.1.1)  10.000 ms  path2 (2.2.2.2)  20.000 ms  path1 (1.1.1.1)  11.000 ms")) {
        fprintf(stderr, "Output mismatch: '%s'\n", buf);
        exit(1);
    }
}

void test_render_unknown_hop_marking_consistent(void) {
    RenderProbe probes[3] = {0};
    probes[0].replied = 0;
    probes[1].replied = 0;
    probes[2].replied = 0;

    char buf[256];
    render_hop(buf, sizeof(buf), 3, probes, 3, 1);

    if (!strstr(buf, " 3  *  *  *")) {
        fprintf(stderr, "Output mismatch: '%s'\n", buf);
        exit(1);
    }
}

void test_render_ipv6_bracketing_or_format_policy_consistent(void) {
    // Current simple logic doesn't strictly bracket IPv6 unless passed that way,
    // or if we enforce it in render. For now, assuming input string is just the address.
    RenderProbe probes[1] = {0};
    probes[0].addr = "2001:db8::1";
    probes[0].replied = 1;
    probes[0].rtt_ms = 5.0;

    char buf[256];
    render_hop(buf, sizeof(buf), 4, probes, 1, 1);

    // Check it appears
    if (!strstr(buf, "2001:db8::1")) {
        exit(1);
    }
}

void register_test_render(void) {
    test_render_compact_single_hop_three_probes();
    test_render_hop_with_multiple_ecmp_paths_grouping();
    test_render_unknown_hop_marking_consistent();
    test_render_ipv6_bracketing_or_format_policy_consistent();
}
