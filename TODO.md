# Modern Path Probe Tool

## Product stance

* **Default mode is unprivileged**: prefer UDP + `IP_RECVERR` / `MSG_ERRQUEUE` correlation (tracepath-style) over raw sockets ([man7.org][1])
* **Correctness beats cleverness**: never “guess” a hop; always report “unknown/no reply” explicitly
* **Structured output is a first-class API**: human output is a view on top of JSONL/JSON
* **Performance is a feature**: avoid per-probe allocations, minimize syscalls, optional in-kernel correlation (eBPF) when available
* **Portable across real deployments**: netns/VRF aware, works in containers, handles policy routing

## Non-goals

* Replacing tcpdump/pcap as a general sniffer
* Doing internal kernel tracing via kprobes as a core dependency (fine for dev tooling, not core)

---

# Architecture deliverables

## Core modules

* `probe/`

  * probe builders: UDP, ICMP echo, TCP SYN
  * per-probe identity: (flow hash, seq/port, ttl, timestamp cookie)
* `io/`

  * send engine: `sendmsg()` batching where possible
  * recv engine: `recvmsg()` normal path + `recvmsg(MSG_ERRQUEUE)` error-queue path
* `correlate/`

  * match replies ↔ probes using error metadata + embedded payload parsing
  * strategy pluggable per probe type (UDP/ICMP/TCP)
* `time/`

  * timestamp policy: userspace clocks vs kernel timestamping (`SO_TIMESTAMPING_*`) ([Kernel Documentation][2])
* `resolve/`

  * async reverse DNS with bounded concurrency + cache
* `render/`

  * terminal view + compact view + “diagnostic” view
* `export/`

  * JSON, JSONL, optional Prometheus textfile exporter

## Optional acceleration modules

* `bpf/`

  * eBPF-based correlation and telemetry
  * ring buffer event stream (libbpf ringbuf) ([Kernel.org][3])
* `xdp/`

  * optional XDP + AF_XDP fast path for high-rate probing/capture ([Kernel Documentation][4])

---

# Backlog (opinionated, prioritized)

## P0 — MVP that’s worth using

### P0.1 Unprivileged core probing (UDP + error queue)

* [x] Implement UDP probes with TTL stepping
* [x] Receive ICMP errors via `IP_RECVERR` ancillary data and `MSG_ERRQUEUE` ([man7.org][1])
* [x] Parse `sock_extended_err` reliably (IPv4 + IPv6 paths)
* **Acceptance**

  * Works without root on a typical distro (only needs standard socket permissions)
  * Correctly prints hop IP for: Time Exceeded, Destination Unreachable
  * Stable correlation under packet reordering

### P0.2 Output engine (human + structured)

* [x] JSONL streaming output (one event per hop/probe)
* [x] Human renderer consumes the same event stream
* **Acceptance**

  * [x] `--jsonl` output is stable schema (versioned)
  * [x] `--quiet` still emits JSONL while suppressing terminal formatting

### P0.3 Baseline correctness + guardrails

* [x] Hard cap on in-flight probes
* [x] Timeouts per hop and overall deadline
* [x] “No reply” is explicit, not inferred
* **Acceptance**

  * [x] Deterministic behavior under loss (`tc netem loss`)
  * [x] No unbounded memory growth on unreachable targets

---

## P1 — Features users notice immediately

### P1.1 Better timestamping (less jitter, better RTT)

* [x] Support `SO_TIMESTAMPING_*` / “NEW” variants when available ([Kernel Documentation][2])
* [x] Provide timestamp modes:

  * [x] `--ts userspace` (default)
  * [x] `--ts kernel-sw`
  * [x] `--ts kernel-hw` (if NIC/driver supports)
* **Acceptance**

  * [x] RTT variance decreases on loaded systems in kernel timestamp modes

### P1.2 Protocol matrix (UDP + ICMP + TCP)

* [x] Add ICMP echo mode (may require CAP_NET_RAW)
* [x] Add TCP SYN mode (useful when UDP/ICMP filtered)
* [x] Auto fallback: UDP → TCP when repeated filtering suspected
* **Acceptance**

  * [x] Same correlation engine works for at least UDP and TCP
  * [x] Clear warning when elevated caps are required

### P1.3 Netns / VRF awareness

* [x] `--netns /proc/<pid>/ns/net` support via `setns()`
* [x] `--iface` / bind-to-device support for VRF-like setups
* **Acceptance**

  * [x] Can trace from inside a container netns without hacks

---

## P2 — “Pro tool” measurement extensions

### P2.1 ECMP / multipath exploration

* `--ecmp N` runs N distinct flow identities per TTL
* Rotate:

  * UDP source ports
  * TCP source ports
  * IPv6 flow label (optional)
* Render as “multiple candidates per hop” (grouped)
* **Acceptance**

  * Demonstrably reveals multiple next-hops behind ECMP

### P2.2 Per-hop MTU discovery

* Detect and report “Packet Too Big” / fragmentation-related feedback
* Emit MTU changes as events
* **Acceptance**

  * Produces actionable MTU drop location with common PMTUD scenarios

### P2.3 Link-layer / interface metadata (best-effort)

* Attempt to report:

  * egress interface index
  * ingress interface index (when derivable)
* **Acceptance**

  * Never blocks core output if metadata unavailable

---

## P3 — eBPF integration (big upgrade, optional)

### P3.1 eBPF correlation + telemetry

* BPF program(s) to observe sends + ICMP receives and correlate in-kernel
* State maps:

  * probe map (LRU hash)
  * per-hop histograms
* Emit hop events via BPF ring buffer ([Kernel.org][3])
* **Acceptance**

  * Userspace does fewer syscalls per probe in BPF mode
  * Ringbuf stream can drive the same JSONL renderer

### P3.2 BPF deploy story (make it painless)

* `--bpf auto|off|on`
* Capability detection and friendly failures
* BPF object shipped as part of build; optionally “CO-RE” style
* **Acceptance**

  * BPF mode fails gracefully (no crash, clear message)

---

## P4 — XDP/AF_XDP “high-rate mode” (only if you truly need it)

### P4.1 AF_XDP plumbing

* XDP program redirects relevant frames to AF_XDP socket buffer ([Kernel Documentation][4])
* Userspace polls XSK rings, parses ICMP replies, correlates
* **Acceptance**

  * Demonstrable throughput win under high probe rates
  * Clear constraints documented (driver support, privileges, hugepages if needed)

---

# Quality plan (what makes it “pro”)

## Testing (must-have)

* Golden tests for correlation logic (hand-constructed ICMP payloads)
* Integration tests with network namespaces + veth + netem (delay/loss/reorder)
* IPv4 + IPv6 test matrix
* Stress tests: large TTL ranges, high probe rates, partial failures
* Fuzz targets

  * ancillary data parsing (cmsg)
  * ICMP parsing (type/code, quoted packet portion)

## Benchmarks (keep it honest)

* probes/sec vs CPU%
* syscalls/probe
* RTT jitter comparison:

  * userspace timestamps vs kernel timestamps ([Kernel Documentation][2])
* Compare modes:

  * error-queue MVP vs BPF ringbuf mode ([Kernel.org][3])
  * optional AF_XDP mode ([Kernel Documentation][4])

## Security & privileges

* Capability-driven modes:

  * unprivileged UDP+ERRQUEUE as default ([man7.org][1])
  * raw ICMP gated behind CAP_NET_RAW
  * BPF gated behind CAP_BPF/CAP_NET_ADMIN (environment-dependent)
* Zero unsafe parsing: strict bounds checks on all quoted-packet parsing

## Docs (minimum bar)

* “How correlation works” (per probe type)
* “Privilege model” table
* “Feature availability” notes (timestamps, BPF ringbuf, AF_XDP) ([Kernel Documentation][2])

---

# Milestones (opinionated roadmap)

## M0 — Skeleton + boring correctness

* repo layout, CLI parsing, JSONL schema v1
* send/recv loops with timeouts
* basic rendering

## M1 — Unprivileged tracer (shipping MVP)

* UDP + ERRQUEUE correlation ([man7.org][1])
* IPv4+IPv6
* stable JSONL output

## M2 — Precision + UX

* kernel timestamping modes ([Kernel Documentation][2])
* resolver cache + bounded parallelism
* better terminal output modes

## M3 — Pro measurement

* ECMP exploration
* per-hop MTU reporting
* namespace support
