# traceroute

A modern, high-performance fork of the classic `traceroute(8)` utility.

Traceroute tracks the route packets take across an IP network to a host. It uses
IP TTL (time to live) and attempts to elicit ICMP TIME_EXCEEDED responses from
intermediate gateways.

## Features

- **Full IPv4 and IPv6 support**.
- **Multiple probing methods**:
  - UDP datagrams (default, unprivileged).
  - ICMP ECHO packets.
  - TCP SYNs (and other TCP requests with flags/options).
  - DCCP Request packets.
  - Generic IP datagrams.
- **Parallel Probing**: Multiple probes in flight with adaptive wait timing.
- **Advanced Network Analysis**: AS path lookups, ICMP extensions (MPLS, Interface Info), and path MTU discovery.
- **Backwards Compatible**: Drop-in replacement for the original traceroute command-line interface.

## Advanced Modern Capabilities

This fork introduces significant architectural improvements and new features:

### 🚀 High-Performance & Unprivileged
- **Unprivileged by default**: Uses UDP + `MSG_ERRQUEUE` correlation (similar to `tracepath`), allowing operation without root privileges for most standard traces.
- **Kernel Timestamping**: Utilizes `SO_TIMESTAMPING` for high-precision nanosecond-level RTT measurements.

### 🔍 Enhanced Visibility & Multipath
- **ECMP Tracing**: Discover load-balanced paths using the `--ecmp` flag to inject distinct flow identities per TTL.
- **IPv6 Flow Labels**: Control IPv6 flow labels directly with `--flowlabel` or let the tool auto-rotate them to exercise network paths.
- **ICMP Extensions**: Full parsing support for RFC 4884 extensions, including MPLS labels and RFC 5837 Interface Information, enabled via `-e`.

### 🤖 Automation & Integration
- **JSONL Output**: Streaming newline-delimited JSON output via `--jsonl`. Ideal for ingestion into logs, databases, or analysis pipelines.
- **Structured Data**: Events are emitted for probe transmission, hop replies, and timeouts, containing full telemetry data.

### ⚡ eBPF & XDP Acceleration
- **eBPF Correlation**: Optional in-kernel event correlation (`--bpf on`) using kprobes to reduce userspace wakeups and capture high-fidelity kernel timestamps.
- **AF_XDP Fast Path**: Support for high-rate probing using AF_XDP for massive topology discovery operations (requires `libxdp`).

## Build

Requirements:
- C compiler (GCC/Clang)
- Meson & Ninja
- `libbpf` and `libxdp` (for BPF/XDP features)

```sh
meson setup build
meson compile -C build
```

## Testing

This project maintains a rigorous unit test suite enforcing core logic correctness, particularly for packet parsing, correlation state machines, and protocol decoding.

```sh
# Run the unit test suite
meson test -C build unit_tests
```

## Usage Examples

```sh
# Basic unprivileged trace
traceroute 8.8.8.8

# JSONL output for scripting/logging
traceroute --jsonl 8.8.8.8

# Discover ECMP paths (send 4 probes with different flow IDs per hop)
traceroute --ecmp 4 -q 4 8.8.8.8

# Show ICMP extensions (MPLS labels, interface info)
traceroute -e 8.8.8.8

# eBPF accelerated mode (requires root/CAP_BPF)
traceroute --bpf on 8.8.8.8

# IPv6 trace with specific flow label
traceroute -6 --flowlabel 12345 google.com
```

## Credits

Written from scratch, influenced by Olaf Kirch's traceroute, Van Jacobson’s
original implementation, and current BSD variants.