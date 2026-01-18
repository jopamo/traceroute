#include <stdio.h>
#include <stdlib.h>
#include "test_suite.h"

int main(int argc, char** argv) {
    printf("Running unit tests...\n");

    register_test_parse_ipv4();
    register_test_parse_ipv6();
    register_test_ipv6_ext();
    register_test_parse_transport();
    register_test_parse_icmp();
    register_test_icmp_quote();
    register_test_cmsg();
    register_test_correlator();
    register_test_flow();
    register_test_rtt();
    register_test_scheduler();
    register_test_dns_cache();
    register_test_json_writer();
    register_test_render();
    register_test_cli();

    printf("All unit tests passed!\n");
    return 0;
}
