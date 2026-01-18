#!/bin/bash
set -e
# This script tries to set up a 2-hop path using namespaces
# ns_client (10.0.1.1) -> ns_router (10.0.1.2, 10.0.2.1) -> ns_target (10.0.2.2)

# We use 'unshare' for the whole thing? No, that's not how it works.
# Usually we need 'ip netns' which uses /run/netns.
# Without root, 'ip netns' fails.

# But maybe we can use 'unshare' to create one namespace, 
# then inside it we have dummy interfaces? No.

echo "Testing if we can use multiple unshares"
