#ifndef TEST_UNIT_COMMON_MOCKS_H
#define TEST_UNIT_COMMON_MOCKS_H

#include "traceroute.h"

extern int debug;
extern unsigned int probes_per_hop;
extern probe* probes;

const char* addr2str(const sockaddr_any* addr);
void add_poll(int fd, int events);
void del_poll(int fd);
probe* probe_by_seq(int seq);
probe* probe_by_sk(int sk);
void probe_done(probe* pb);
void parse_icmp_res(probe* pb, int type, int code, int info);

#endif /* TEST_UNIT_COMMON_MOCKS_H */
