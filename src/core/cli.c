#include "cli.h"
#include <string.h>
#include <stdlib.h>

void cli_set_defaults(CLIConfig* cfg) {
    if (!cfg)
        return;
    cfg->max_hops = 30;
    cfg->first_hop = 1;
    cfg->wait_secs = 5.0;
    cfg->queries = 3;
    cfg->module_name = "default";
    cfg->af = 0;  // Auto
    cfg->netns = NULL;
    cfg->json = 0;
}

int cli_validate(CLIConfig* cfg) {
    if (!cfg)
        return -1;

    if (cfg->max_hops < 1 || cfg->max_hops > 255)
        return -1;
    if (cfg->first_hop < 1 || cfg->first_hop > cfg->max_hops)
        return -1;
    if (cfg->wait_secs <= 0.0 || cfg->wait_secs > 86400.0)
        return -1;  // Sanity check
    if (cfg->queries < 1 || cfg->queries > 16)
        return -1;  // Limit queries per hop sanity

    // Netns validation
    if (cfg->netns) {
        if (strlen(cfg->netns) == 0 || strlen(cfg->netns) > 255)
            return -1;
        if (cfg->netns[0] == '/') {
            // Absolute path required usually, or just check sane chars
            // Basic check: no ".." to prevent traversal if it matters (though usually root runs this)
            if (strstr(cfg->netns, ".."))
                return -1;
        }
        else {
            // Must be a name, so no slashes allowed typically unless it's a path
            // But 'ip netns' accepts names in /var/run/netns.
            // Let's assume strict rule: if it contains '/', it must start with '/'
            if (strchr(cfg->netns, '/') != NULL && cfg->netns[0] != '/')
                return -1;
        }
    }

    // Protocol check
    if (cfg->module_name) {
        if (strcmp(cfg->module_name, "default") != 0 && strcmp(cfg->module_name, "icmp") != 0 &&
            strcmp(cfg->module_name, "udp") != 0 && strcmp(cfg->module_name, "tcp") != 0 &&
            strcmp(cfg->module_name, "tcpconn") != 0 && strcmp(cfg->module_name, "raw") != 0 &&
            strcmp(cfg->module_name, "dccp") != 0 && strcmp(cfg->module_name, "udplite") != 0) {
            return -1;
        }
    }

    return 0;
}
