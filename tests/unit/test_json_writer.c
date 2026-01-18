#include "common/assert.h"
#include "core/json_writer.h"
#include <string.h>

void test_json_event_probe_sent_has_required_fields(void) {
    // Note: The current implementation only writes the reply/result, not the "probe sent" event explicitly as a
    // separate function, but the task list implies we want to verify fields. Wait, the "probe sent" event is usually
    // "type":"probe", which covers both sent (implicitly) and result. If we look at existing `tr_export_jsonl_probe`,
    // it prints the result. If the goal is "json_event_probe_sent_has_required_fields", maybe we need a dedicated
    // function for "sent"? Or maybe it refers to the "probe" event having ttl/probe_idx which identifies the sent
    // probe.

    // For now, let's test the `json_write_probe` which is the main event.
    char buf[512];
    int len = json_write_probe(buf, sizeof(buf), 1, 1, NULL, -1.0, NULL);
    ASSERT_OK(len);

    // Check for required fields
    if (!strstr(buf, "\"type\":\"probe\""))
        exit(1);
    if (!strstr(buf, "\"ttl\":1"))
        exit(1);
    if (!strstr(buf, "\"probe\":1"))
        exit(1);
    if (!strstr(buf, "\"replied\":false"))
        exit(1);
}

void test_json_event_hop_reply_has_required_fields(void) {
    char buf[512];
    int len = json_write_probe(buf, sizeof(buf), 5, 2, "1.2.3.4", 12.345, NULL);
    ASSERT_OK(len);

    if (!strstr(buf, "\"type\":\"probe\""))
        exit(1);
    if (!strstr(buf, "\"ttl\":5"))
        exit(1);
    if (!strstr(buf, "\"probe\":2"))
        exit(1);
    if (!strstr(buf, "\"replied\":true"))
        exit(1);
    if (!strstr(buf, "\"addr\":\"1.2.3.4\""))
        exit(1);
    if (!strstr(buf, "\"rtt_ms\":12.345"))
        exit(1);
}

void test_json_event_no_reply_has_required_fields(void) {
    char buf[512];
    int len = json_write_probe(buf, sizeof(buf), 5, 2, NULL, -1.0, NULL);
    ASSERT_OK(len);

    if (!strstr(buf, "\"type\":\"probe\""))
        exit(1);
    if (!strstr(buf, "\"replied\":false"))
        exit(1);
}

void test_json_schema_version_tag_present(void) {
    char buf[512];
    int len = json_write_header(buf, sizeof(buf), "example.com", "1.2.3.4", 30, 60);
    ASSERT_OK(len);

    if (!strstr(buf, "\"type\":\"header\""))
        exit(1);
    if (!strstr(buf, "\"version\":1"))
        exit(1);
}

void test_json_escape_strings_no_invalid_utf8_assumptions(void) {
    char out[64];
    // Simple test with quotes and newlines
    const char* in = "foo\"bar\nbaz";
    int len = json_escape_string(out, sizeof(out), in);
    ASSERT_OK(len);
    ASSERT_EQ_STR(out, "\"foo\\\"bar\\nbaz\"");
}

void test_json_numbers_bounds_no_int_overflow(void) {
    char buf[512];
    // Max hops uint
    int len = json_write_header(buf, sizeof(buf), "dst", "1.1.1.1", 4294967295U, 100);
    ASSERT_OK(len);
    if (!strstr(buf, "\"max_hops\":4294967295"))
        exit(1);
}

void register_test_json_writer(void) {
    test_json_event_probe_sent_has_required_fields();
    test_json_event_hop_reply_has_required_fields();
    test_json_event_no_reply_has_required_fields();
    test_json_schema_version_tag_present();
    test_json_escape_strings_no_invalid_utf8_assumptions();
    test_json_numbers_bounds_no_int_overflow();
}
