#include "common/assert.h"
#include "core/cli.h"

void test_cli_defaults_sane(void) {
    CLIConfig cfg;
    cli_set_defaults(&cfg);
    ASSERT_EQ_INT(cfg.max_hops, 30);
    ASSERT_EQ_INT(cfg.queries, 3);
    ASSERT_OK(cli_validate(&cfg));
}

void test_cli_rejects_invalid_max_hops(void) {
    CLIConfig cfg;
    cli_set_defaults(&cfg);
    cfg.max_hops = 256;
    ASSERT_EQ_INT(cli_validate(&cfg), -1);

    cfg.max_hops = 0;
    ASSERT_EQ_INT(cli_validate(&cfg), -1);
}

void test_cli_rejects_invalid_timeout_values(void) {
    CLIConfig cfg;
    cli_set_defaults(&cfg);
    cfg.wait_secs = -1.0;
    ASSERT_EQ_INT(cli_validate(&cfg), -1);

    cfg.wait_secs = 0.0;
    ASSERT_EQ_INT(cli_validate(&cfg), -1);
}

void test_cli_protocol_selection_matrix(void) {
    CLIConfig cfg;
    cli_set_defaults(&cfg);

    cfg.module_name = "udp";
    ASSERT_OK(cli_validate(&cfg));

    cfg.module_name = "tcp";
    ASSERT_OK(cli_validate(&cfg));

    cfg.module_name = "invalid_proto";
    ASSERT_EQ_INT(cli_validate(&cfg), -1);
}

void test_cli_netns_path_validation(void) {
    CLIConfig cfg;
    cli_set_defaults(&cfg);

    cfg.netns = "blue";
    ASSERT_OK(cli_validate(&cfg));

    cfg.netns = "/var/run/netns/blue";
    ASSERT_OK(cli_validate(&cfg));

    // Invalid path (relative with slash)
    cfg.netns = "var/blue";
    ASSERT_EQ_INT(cli_validate(&cfg), -1);

    // Traversal attempt
    cfg.netns = "/var/../etc/passwd";
    ASSERT_EQ_INT(cli_validate(&cfg), -1);
}

void register_test_cli(void) {
    test_cli_defaults_sane();
    test_cli_rejects_invalid_max_hops();
    test_cli_rejects_invalid_timeout_values();
    test_cli_protocol_selection_matrix();
    test_cli_netns_path_validation();
}
