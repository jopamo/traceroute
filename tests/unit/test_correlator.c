#include "common/assert.h"
#include "correlate/correlator.h"
#include <netinet/in.h>
#include <string.h>

void test_corr_insert_probe_then_match_reply_success(void) {
    Correlator* c = corr_create(10);

    Probe p = {0};
    p.id.protocol = IPPROTO_UDP;
    p.id.dst_port = 33434;
    p.id.src_port = 12345;

    corr_insert_probe(c, &p);

    PacketResult res = {0};
    res.type = RESULT_ERROR;
    res.original_req.protocol = IPPROTO_UDP;
    res.original_req.dst_port = 33434;
    res.original_req.src_port = 12345;

    Probe* matched = corr_match(c, &res);
    ASSERT_EQ_PTR(matched, &c->entries[0]);

    corr_destroy(c);
}

void test_corr_match_reply_missing_probe_is_unknown(void) {
    Correlator* c = corr_create(10);

    PacketResult res = {0};
    res.original_req.protocol = IPPROTO_UDP;
    res.original_req.dst_port = 33434;

    Probe* matched = corr_match(c, &res);
    ASSERT_EQ_PTR(matched, NULL);

    corr_destroy(c);
}

void test_corr_multiple_inflight_out_of_order_replies(void) {
    Correlator* c = corr_create(10);

    Probe p1 = {0};
    p1.id.dst_port = 33434;
    corr_insert_probe(c, &p1);

    Probe p2 = {0};
    p2.id.dst_port = 33435;
    corr_insert_probe(c, &p2);

    PacketResult res2 = {0};
    res2.original_req.dst_port = 33435;
    ASSERT_EQ_PTR(corr_match(c, &res2), &c->entries[1]);

    PacketResult res1 = {0};
    res1.original_req.dst_port = 33434;
    ASSERT_EQ_PTR(corr_match(c, &res1), &c->entries[0]);

    corr_destroy(c);
}

void test_corr_capacity_limits_enforced_no_alloc_growth(void) {
    Correlator* c = corr_create(2);

    Probe p1 = {0};
    p1.id.dst_port = 1;
    Probe p2 = {0};
    p2.id.dst_port = 2;
    Probe p3 = {0};
    p3.id.dst_port = 3;

    corr_insert_probe(c, &p1);
    corr_insert_probe(c, &p2);
    corr_insert_probe(c, &p3);  // Should evict p1

    ASSERT_EQ_U64(c->count, 2);

    PacketResult res1 = {0};
    res1.original_req.dst_port = 1;
    ASSERT_EQ_PTR(corr_match(c, &res1), NULL);

    PacketResult res3 = {0};
    res3.original_req.dst_port = 3;
    ASSERT_EQ_PTR(corr_match(c, &res3), &c->entries[0]);  // p3 should be at index 0 (evicted p1)

    corr_destroy(c);
}

void register_test_correlator(void) {
    test_corr_insert_probe_then_match_reply_success();
    test_corr_match_reply_missing_probe_is_unknown();
    test_corr_multiple_inflight_out_of_order_replies();
    test_corr_capacity_limits_enforced_no_alloc_growth();
}
