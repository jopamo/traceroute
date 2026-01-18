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

## Modern Features

- **Unprivileged by default**: Prefer UDP + error queue correlation (tracepath-style) for root-less operation.
- **Structured Output**: JSONL streaming output via `--jsonl` for easy integration with other tools.
- **High Precision**: Kernel-level timestamping (`SO_TIMESTAMPING`) for accurate RTT measurements.
- **eBPF Acceleration**: Optional in-kernel correlation and telemetry via eBPF kprobes.
- **AF_XDP Fast Path**: High-rate probing support using AF_XDP for massive trace operations.
- **Deterministic Correlation**: Reliable matching of replies even under heavy packet reordering.

## Build

```sh
meson setup build
meson compile -C build
```

## Usage

```sh
# Basic unprivileged trace
traceroute 8.8.8.8

# JSONL output for scripting
traceroute --jsonl 8.8.8.8

# eBPF accelerated mode
traceroute --bpf on 8.8.8.8

# High-rate AF_XDP mode (requires CAP_NET_RAW and CAP_BPF)
traceroute -i eth0 --xdp 8.8.8.8
```

## Credits

Written from scratch, influenced by Olaf Kirch's traceroute, Van Jacobson’s
original implementation, and current BSD variants.
