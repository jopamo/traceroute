# traceroute

fork of Dmitry Butskoy's implementation of the `traceroute(8)` utility

Traceroute tracks the route packets take across an IP network to a host. It uses
IP TTL (time to live) and attempts to elicit ICMP TIME_EXCEEDED responses from
intermediate gateways.

## Features

- Full support for IPv4 and IPv6.
- Multiple probing methods:
  - UDP datagrams (including udplite and UDP to a particular port)
  - ICMP ECHO packets (including datagram ICMP sockets)
  - TCP SYNs (and other TCP requests with flags/options)
  - DCCP Request packets
  - Generic IP datagrams
- UDP methods do not require root privileges.
- Multiple probes in flight with adaptive wait timing.
- AS path lookups, ICMP extensions (including MPLS), and path MTU discovery.
- Command-line compatibility with the original traceroute.

## Build

```sh
meson setup build
meson compile -C build
sudo meson install -C build
```

## Credits

Written from scratch, influenced by Olaf Kirch's traceroute, Van Jacobson’s
original implementation, and current BSD variants.

Original author : <Dmitry at Butskoy dot name>.
