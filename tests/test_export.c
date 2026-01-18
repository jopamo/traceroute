#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "traceroute.h"

static char capture_buf[4096];
static FILE* old_stdout;

static void start_capture(void) {
    fflush(stdout);
    old_stdout = stdout;
    stdout = tmpfile();
    if (!stdout) {
        fprintf(stderr, "FAIL: tmpfile() for capture\n");
        exit(1);
    }
}

static void stop_capture(void) {
    rewind(stdout);
    memset(capture_buf, 0, sizeof(capture_buf));
    size_t n = fread(capture_buf, 1, sizeof(capture_buf) - 1, stdout);
    capture_buf[n] = '\0';
    fclose(stdout);
    stdout = old_stdout;
}

#define EXPECT_TRUE(cond, msg)            \
    do {                                  \
        if (!(cond)) {                    \
            fprintf(stderr, "%s\n", msg); \
            return 1;                     \
        }                                 \
    } while (0)

// Mock globals
unsigned int probes_per_hop = 3;
probe* probes = NULL;

// Mock addr2str
const char* addr2str(const sockaddr_any* addr) {
    if (addr->sa.sa_family == AF_INET)
        return "1.2.3.4";
    if (addr->sa.sa_family == AF_INET6)
        return "::1";
    return "unknown";
}

int main() {
    printf("Running Export Tests...\n");

    probes = calloc(10, sizeof(probe));
    if (!probes) {
        fprintf(stderr, "FAIL: probes allocation\n");
        return 1;
    }

    // Test Header
    sockaddr_any dst;
    memset(&dst, 0, sizeof(dst));
    dst.sa.sa_family = AF_INET;
    printf("Header test:\n");
    start_capture();
    tr_export_jsonl_header("example.com", &dst, 30, 60);
    stop_capture();
    EXPECT_TRUE(strstr(capture_buf, "\"type\":\"header\"") != NULL, "FAIL: header missing type");
    EXPECT_TRUE(strstr(capture_buf, "\"dst_name\":\"example.com\"") != NULL, "FAIL: header missing dst_name");

    // Test Probe Basic
    probes[0].res.sa.sa_family = AF_INET;
    probes[0].send_time = 100.0;
    probes[0].recv_time = 100.005;  // 5ms
    printf("Probe basic test:\n");
    start_capture();
    tr_export_jsonl_probe(&probes[0]);
    stop_capture();
    EXPECT_TRUE(strstr(capture_buf, "\"type\":\"probe\"") != NULL, "FAIL: probe missing type");
    EXPECT_TRUE(strstr(capture_buf, "\"rtt_ms\":5.000") != NULL, "FAIL: probe missing rtt_ms");

    // Test Probe with Error
    probes[1].res.sa.sa_family = AF_INET;
    probes[1].send_time = 100.0;
    probes[1].recv_time = 100.005;
    strcpy(probes[1].err_str, "!N");
    printf("Probe error test:\n");
    start_capture();
    tr_export_jsonl_probe(&probes[1]);
    stop_capture();
    EXPECT_TRUE(strstr(capture_buf, "\"err\":\"!N\"") != NULL, "FAIL: probe missing err");

    // Test Probe with Extension
    probes[2].res.sa.sa_family = AF_INET;
    probes[2].send_time = 100.0;
    probes[2].recv_time = 100.005;
    probes[2].ext = strdup("MPLS:L=100,E=0,S=1,T=1");
    printf("Probe extension test:\n");
    start_capture();
    tr_export_jsonl_probe(&probes[2]);
    stop_capture();
    EXPECT_TRUE(strstr(capture_buf, "\"extensions\":\"MPLS:L=100,E=0,S=1,T=1\"") != NULL,
                "FAIL: probe missing extensions");

    // Test No Reply
    memset(&probes[4], 0, sizeof(probe));
    printf("Probe no-reply test:\n");
    start_capture();
    tr_export_jsonl_probe(&probes[4]);
    stop_capture();
    EXPECT_TRUE(strstr(capture_buf, "\"replied\":false") != NULL, "FAIL: probe missing replied:false");

    // Test JSON escaping
    probes[3].res.sa.sa_family = AF_INET;
    probes[3].send_time = 100.0;
    probes[3].recv_time = 100.005;
    probes[3].ext = strdup("Quote: \"Test\", Backslash: \\\\ ");
    printf("Probe escaping test:\n");
    start_capture();
    tr_export_jsonl_probe(&probes[3]);
    stop_capture();
    EXPECT_TRUE(strstr(capture_buf, "\"extensions\"") != NULL, "FAIL: probe missing extensions field");
    EXPECT_TRUE(strstr(capture_buf, "\\\"Test\\\"") != NULL, "FAIL: probe missing escaped quotes");
    EXPECT_TRUE(strstr(capture_buf, "\\\\\\\\") != NULL, "FAIL: probe missing escaped backslash");

    // Test MTU and Interfaces
    probes[5].res.sa.sa_family = AF_INET;
    probes[5].send_time = 100.0;
    probes[5].recv_time = 100.005;
    probes[5].mtu = 1492;
    probes[5].ifindex_in = 2;
    probes[5].ifindex_out = 3;
    printf("Probe MTU and Interfaces test:\n");
    start_capture();
    tr_export_jsonl_probe(&probes[5]);
    stop_capture();
    EXPECT_TRUE(strstr(capture_buf, "\"mtu\":1492") != NULL, "FAIL: probe missing mtu");
    EXPECT_TRUE(strstr(capture_buf, "\"ifindex_in\":2") != NULL, "FAIL: probe missing ifindex_in");
    EXPECT_TRUE(strstr(capture_buf, "\"ifindex_out\":3") != NULL, "FAIL: probe missing ifindex_out");

    // Test End
    printf("End test:\n");
    start_capture();
    tr_export_jsonl_end();
    stop_capture();
    EXPECT_TRUE(strstr(capture_buf, "\"type\":\"end\"") != NULL, "FAIL: end missing type");

    free(probes[2].ext);
    free(probes[3].ext);
    free(probes);
    return 0;
}
