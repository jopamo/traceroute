#ifndef TEST_UNIT_TEST_SUITE_H
#define TEST_UNIT_TEST_SUITE_H

void register_test_parse_ipv4(void);
void register_test_parse_ipv6(void);
void register_test_ipv6_ext(void);
void register_test_parse_transport(void);
void register_test_parse_icmp(void);
void register_test_icmp_quote(void);
void register_test_cmsg(void);
void register_test_correlator(void);
void register_test_flow(void);
void register_test_rtt(void);
void register_test_scheduler(void);

#endif /* TEST_UNIT_TEST_SUITE_H */
