#include "mocks.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <stdlib.h>

int debug = 0;
unsigned int probes_per_hop = 3;
probe* probes = NULL;

static char addr2str_buf[INET6_ADDRSTRLEN];

const char* addr2str(const sockaddr_any* addr) {
    if (addr->sa.sa_family == AF_INET) {
        inet_ntop(AF_INET, &addr->sin.sin_addr, addr2str_buf, sizeof(addr2str_buf));
    }
    else if (addr->sa.sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &addr->sin6.sin6_addr, addr2str_buf, sizeof(addr2str_buf));
    }
    else {
        strcpy(addr2str_buf, "unknown");
    }
    return addr2str_buf;
}

void add_poll(int fd, int events) {
    (void)fd;
    (void)events;
}
void del_poll(int fd) {
    (void)fd;
}

probe* probe_by_seq(int seq) {
    if (!probes)
        return NULL;
    // Simple mock search
    for (int i = 0; i < 100; i++) {
        if (probes[i].seq == seq)
            return &probes[i];
    }
    return NULL;
}

probe* probe_by_sk(int sk) {
    if (!probes)
        return NULL;
    for (int i = 0; i < 100; i++) {
        if (probes[i].sk == sk)
            return &probes[i];
    }
    return NULL;
}

void probe_done(probe* pb) {
    pb->done = 1;
}

void parse_icmp_res(probe* pb, int type, int code, int info) {
    (void)info;
    if (type == ICMP_TIME_EXCEEDED || type == ICMP_DEST_UNREACH) {
        pb->final = 1;
    }
}
