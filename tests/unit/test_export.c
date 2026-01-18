#include "common/assert.h"
#include "common/mocks.h"
#include "traceroute.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Use common mocks */

/* We need to capture stdout to test export functions */
static char capture_buf[4096];
static FILE* old_stdout;

static void start_capture(void) {
    fflush(stdout);
    old_stdout = stdout;
    stdout = tmpfile();
    ASSERT_TRUE(stdout != NULL);
}

static void stop_capture(void) {
    rewind(stdout);
    memset(capture_buf, 0, sizeof(capture_buf));
    size_t n = fread(capture_buf, 1, sizeof(capture_buf) - 1, stdout);
    capture_buf[n] = '\0';
    fclose(stdout);
    stdout = old_stdout;
}

void test_export_jsonl_header(void) {
    sockaddr_any dst = {0};
    dst.sa.sa_family = AF_INET;

    start_capture();
    tr_export_jsonl_header("example.com", &dst, 30, 60);
    stop_capture();

    ASSERT_TRUE(strstr(capture_buf, "\"type\":\"header\"") != NULL);
    ASSERT_TRUE(strstr(capture_buf, "\"dst_name\":\"example.com\"") != NULL);
}

void test_export_jsonl_probe(void) {
    probes = calloc(10, sizeof(probe));
    probes[0].res.sa.sa_family = AF_INET;
    probes[0].send_time = 100.0;
    probes[0].recv_time = 100.005;

    start_capture();
    tr_export_jsonl_probe(&probes[0]);
    stop_capture();

    ASSERT_TRUE(strstr(capture_buf, "\"type\":\"probe\"") != NULL);
    ASSERT_TRUE(strstr(capture_buf, "\"rtt_ms\":5.0") != NULL);
    free(probes);
    probes = NULL;
}

void register_test_export(void) {
    test_export_jsonl_header();
    test_export_jsonl_probe();
}
