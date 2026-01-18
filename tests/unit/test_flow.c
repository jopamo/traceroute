#include "common/assert.h"
#include "correlate/flow.h"

void test_flowid_udp_ports_derive_unique_per_probe(void) {
    FlowIdentity f0, f1;
    flow_derive_udp(&f0, 33434, 12345, 0);
    flow_derive_udp(&f1, 33434, 12345, 1);

    ASSERT_EQ_INT(f0.dst_port, 33434);
    ASSERT_EQ_INT(f1.dst_port, 33435);
    ASSERT_EQ_INT(f0.src_port, 12345);
    ASSERT_EQ_INT(f1.src_port, 12345);
}

void test_flowid_tcp_ports_derive_unique_per_probe(void) {
    FlowIdentity f0, f1;
    flow_derive_tcp(&f0, 80, 10000, 0);
    flow_derive_tcp(&f1, 80, 10000, 1);

    ASSERT_EQ_INT(f0.dst_port, 80);
    ASSERT_EQ_INT(f1.dst_port, 80);
    ASSERT_EQ_INT(f0.src_port, 10000);
    ASSERT_EQ_INT(f1.src_port, 10001);
}

void test_flowid_stability_given_same_inputs(void) {
    FlowIdentity f0, f1;
    flow_derive_udp(&f0, 33434, 12345, 5);
    flow_derive_udp(&f1, 33434, 12345, 5);

    ASSERT_EQ_INT(f0.dst_port, f1.dst_port);
    ASSERT_EQ_INT(f0.src_port, f1.src_port);
}

void test_flowid_ipv6_flowlabel_rotation_optional(void) {
    FlowIdentity f0, f1;
    flow_derive_ipv6(&f0, 0x12345, 0);
    flow_derive_ipv6(&f1, 0x12345, 1);

    ASSERT_EQ_INT(f0.flow_label, 0x12345);
    ASSERT_EQ_INT(f1.flow_label, 0x12346);
}

void register_test_flow(void) {
    test_flowid_udp_ports_derive_unique_per_probe();
    test_flowid_tcp_ports_derive_unique_per_probe();
    test_flowid_stability_given_same_inputs();
    test_flowid_ipv6_flowlabel_rotation_optional();
}
