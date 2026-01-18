#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "traceroute.h"

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

    // Test Header
    sockaddr_any dst;
    memset(&dst, 0, sizeof(dst));
    dst.sa.sa_family = AF_INET;
    printf("Header test:\n");
    tr_export_jsonl_header("example.com", &dst, 30, 60);

    // Test Probe Basic
    probes[0].res.sa.sa_family = AF_INET;
    probes[0].send_time = 100.0;
    probes[0].recv_time = 100.005;  // 5ms
    printf("Probe basic test:\n");
    tr_export_jsonl_probe(&probes[0]);

    // Test Probe with Error
    probes[1].res.sa.sa_family = AF_INET;
    probes[1].send_time = 100.0;
    probes[1].recv_time = 100.005;
    strcpy(probes[1].err_str, "!N");
    printf("Probe error test:\n");
    tr_export_jsonl_probe(&probes[1]);

    // Test Probe with Extension
    probes[2].res.sa.sa_family = AF_INET;
    probes[2].send_time = 100.0;
    probes[2].recv_time = 100.005;
    probes[2].ext = strdup("MPLS:L=100,E=0,S=1,T=1");
    printf("Probe extension test:\n");
    tr_export_jsonl_probe(&probes[2]);

    // Test No Reply
    memset(&probes[4], 0, sizeof(probe));
    printf("Probe no-reply test:\n");
    tr_export_jsonl_probe(&probes[4]);

    // Test JSON escaping
    probes[3].res.sa.sa_family = AF_INET;
    probes[3].send_time = 100.0;
    probes[3].recv_time = 100.005;
    probes[3].ext = strdup("Quote: \"Test\", Backslash: \\\\ ");
    printf("Probe escaping test:\n");
    tr_export_jsonl_probe(&probes[3]);

    // Test End
    printf("End test:\n");
    tr_export_jsonl_end();

    free(probes[2].ext);
    free(probes[3].ext);
    free(probes);
    return 0;
}
