#include "common/assert.h"
#include "core/scheduler.h"

void test_rate_limit_tokens_basic(void) {
    TokenBucket tb;
    token_bucket_init(&tb, 10.0, 10.0, 100.0);

    // Should be able to consume 10 tokens immediately
    ASSERT_EQ_INT(token_bucket_consume(&tb, 10.0, 100.0), 1);

    // Should fail to consume more
    ASSERT_EQ_INT(token_bucket_consume(&tb, 1.0, 100.0), 0);
}

void test_rate_limit_burst_then_refill(void) {
    TokenBucket tb;
    token_bucket_init(&tb, 1.0, 2.0, 100.0);

    // Consume burst
    ASSERT_EQ_INT(token_bucket_consume(&tb, 2.0, 100.0), 1);
    ASSERT_EQ_INT(token_bucket_consume(&tb, 1.0, 100.0), 0);

    // Wait 1 second (at rate 1.0) -> refill 1 token
    ASSERT_EQ_INT(token_bucket_consume(&tb, 1.0, 101.0), 1);
}

void test_schedule_ttl_step_sequence_correct(void) {
    ProbeScheduler s;
    scheduler_init(&s, 2, 2, 1, 0);  // 2 TTLs, 2 probes per TTL

    int ttl, probe_idx;

    // TTL 1, Probe 0
    ASSERT_EQ_INT(scheduler_next_probe(&s, &ttl, &probe_idx, 100.0), 1);
    ASSERT_EQ_INT(ttl, 1);
    ASSERT_EQ_INT(probe_idx, 0);

    // TTL 1, Probe 1
    ASSERT_EQ_INT(scheduler_next_probe(&s, &ttl, &probe_idx, 100.0), 1);
    ASSERT_EQ_INT(ttl, 1);
    ASSERT_EQ_INT(probe_idx, 1);

    // TTL 2, Probe 0
    ASSERT_EQ_INT(scheduler_next_probe(&s, &ttl, &probe_idx, 100.0), 1);
    ASSERT_EQ_INT(ttl, 2);
    ASSERT_EQ_INT(probe_idx, 0);

    // TTL 2, Probe 1
    ASSERT_EQ_INT(scheduler_next_probe(&s, &ttl, &probe_idx, 100.0), 1);
    ASSERT_EQ_INT(ttl, 2);
    ASSERT_EQ_INT(probe_idx, 1);

    // Done
    ASSERT_EQ_INT(scheduler_next_probe(&s, &ttl, &probe_idx, 100.0), 0);
}

void test_schedule_parallel_probes_per_ttl_respected(void) {
    // Current simple scheduler doesn't enforce parallel limits internally (logic is external),
    // but we can verify the state transitions match expectation.
    // This test is redundant with above but explicit about intent.
    ProbeScheduler s;
    scheduler_init(&s, 1, 3, 1, 0);

    int ttl, probe_idx;

    ASSERT_EQ_INT(scheduler_next_probe(&s, &ttl, &probe_idx, 100.0), 1);
    ASSERT_EQ_INT(probe_idx, 0);
    ASSERT_EQ_INT(scheduler_next_probe(&s, &ttl, &probe_idx, 100.0), 1);
    ASSERT_EQ_INT(probe_idx, 1);
    ASSERT_EQ_INT(scheduler_next_probe(&s, &ttl, &probe_idx, 100.0), 1);
    ASSERT_EQ_INT(probe_idx, 2);
    ASSERT_EQ_INT(scheduler_next_probe(&s, &ttl, &probe_idx, 100.0), 0);
}

void test_schedule_deadline_stops_new_probes(void) {
    ProbeScheduler s;
    scheduler_init(&s, 10, 1, 1, 200.0);

    int ttl, probe_idx;
    ASSERT_EQ_INT(scheduler_next_probe(&s, &ttl, &probe_idx, 199.0), 1);
    ASSERT_EQ_INT(scheduler_next_probe(&s, &ttl, &probe_idx, 201.0), 0);
}

void register_test_scheduler(void) {
    test_rate_limit_tokens_basic();
    test_rate_limit_burst_then_refill();
    test_schedule_ttl_step_sequence_correct();
    test_schedule_parallel_probes_per_ttl_respected();
    test_schedule_deadline_stops_new_probes();
}
