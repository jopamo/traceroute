#include "common/assert.h"
#include "correlate/rtt.h"

void test_rtt_userspace_monotonic_compute_nonnegative(void) {
    double rtt = calculate_rtt(100.0, 100.05);  // 50ms
    if (rtt < 49.9 || rtt > 50.1) {
        fprintf(stderr, "RTT mismatch: %f\n", rtt);
        exit(1);
    }
}

void test_rtt_clamps_or_rejects_clock_skew_cases(void) {
    double rtt = calculate_rtt(100.0, 99.0);
    if (rtt != -2.0) {
        fprintf(stderr, "Should have rejected clock skew, got %f\n", rtt);
        exit(1);
    }
}

void register_test_rtt(void) {
    test_rtt_userspace_monotonic_compute_nonnegative();
    test_rtt_clamps_or_rejects_clock_skew_cases();
}
