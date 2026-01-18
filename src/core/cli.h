#ifndef TRACEROUTE_CORE_CLI_H
#define TRACEROUTE_CORE_CLI_H

typedef struct {
    int max_hops;
    int first_hop;
    double wait_secs;
    int queries;
    const char* module_name;
    const char* dst_name;
    const char* netns;
    int af;    // AF_INET or AF_INET6
    int json;  // boolean
} CLIConfig;

void cli_set_defaults(CLIConfig* cfg);
int cli_validate(CLIConfig* cfg);

#endif /* TRACEROUTE_CORE_CLI_H */
