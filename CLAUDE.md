# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

XDPunk is a thesis project implementing a programmable L3 network switch using eBPF/XDP on Linux. It demonstrates high-performance in-kernel packet forwarding with dynamic, externally-controlled routing tables—separating control plane (user-space) from data plane (kernel).

## Build & Run Commands

### Prerequisites & Environment Setup

```bash
# Install dependencies (Debian/Ubuntu)
sudo bash scripts/install.sh

# Clean up any previous state
sudo bash scripts/reset.sh
```

**Required packages:**
- Build tools: `clang`, `llvm`, `gcc-multilib`, `linux-headers`, `build-essential`
- Runtime: `libbpf-dev`, `bpftool`, `linux-libc-dev`, `python3-bpfcc`, `python3-pip`
- Environment: Linux kernel with eBPF/XDP support, running with `CAP_SYS_ADMIN` privileges

### Build & Deploy XDP Program

The eBPF/XDP program is built from source and loaded into the kernel:

```bash
# Compile C to eBPF bytecode (done automatically by setup scripts)
clang -O2 -g -target bpf -c xdp/xdp_forward_dynamic.c -o /tmp/xdp_forward_dynamic.o

# Load and pin the program (done by bpftool in setup)
bpftool prog load /tmp/xdp_forward_dynamic.o /sys/fs/bpf/xdp_fwd pinmaps /sys/fs/bpf/xdp_fwd_maps

# Attach to virtual interfaces
ip -n nssw link set dev veth1s xdpgeneric pinned /sys/fs/bpf/xdp_fwd
```

### Setup & Test Workflow

```bash
# 1. Create virtual network lab with 3 isolated namespaces and dynamic routing
sudo bash scripts/setup_xdp_l3_dynamic.sh

# 2. Verify routing table is populated
sudo bpftool map dump pinned /sys/fs/bpf/xdp_fwd_maps/route_table

# 3. OR use the Python CLI (higher-level interface)
sudo xdpunk-cli map dump

# 4. Test connectivity between namespaces
ip netns exec ns1 ping 10.0.0.2

# 5. Monitor traffic in another terminal
ip netns exec ns3 tcpdump -i veth3h
```

### Control Plane Commands (Route Management)

The Python CLI (`xdpunk-cli`) manages the kernel's routing table without recompiling:

```bash
# List all active routes
sudo xdpunk-cli map dump

# Query a specific route
sudo xdpunk-cli map lookup 10.0.0.1

# Add or update a route (IP → interface)
sudo xdpunk-cli map update 10.0.0.3 veth3s

# Delete a route
sudo xdpunk-cli map delete 10.0.0.3

# Clear all routes
sudo xdpunk-cli map flush

# Use alternate namespace or BPF map path
sudo xdpunk-cli --netns mynamespace --map-pin /sys/fs/bpf/custom map dump
```

### Cleanup

```bash
# Remove all namespaces, BPF programs, and pins
sudo bash scripts/reset.sh
```

## Architecture & Design

### High-Level Data Flow

1. **Kernel Data Plane (XDP)**
   - Packet arrives at network interface
   - XDP program (in `xdp/xdp_forward_dynamic.c`) intercepts at driver level
   - Extracts destination IP from packet header (IPv4 or ARP)
   - Looks up IP in `route_table` BPF map
   - Redirects packet to output interface via `bpf_redirect()`

2. **User-Space Control Plane (Python)**
   - CLI tool (`userspace/xdpunk_cli.py`) reads/writes to pinned BPF maps
   - Resolves interface names to kernel ifindex within switch namespace
   - Updates routing table at runtime without kernel recompilation

3. **Virtual Lab Environment**
   - 3 isolated network namespaces (ns1, ns2, ns3) simulate end hosts
   - 1 switch namespace (nssw) where XDP runs
   - Virtual ethernet pairs (veths) connect hosts to switch
   - Initial routes: 10.0.0.1→veth1s (ns1), 10.0.0.2→veth2s (ns2), 10.0.0.3→veth3s (ns3)

### Key Components

| Component | File(s) | Role |
|-----------|---------|------|
| **XDP Forwarding Logic** | `xdp/xdp_forward_dynamic.c` | Kernel data plane; performs L3 lookup and packet redirection |
| **BPF Map** | (in-kernel, pinned at `/sys/fs/bpf/xdp_fwd_maps/route_table`) | Hash map: IPv4 destination → interface index |
| **Setup Scripts** | `scripts/setup_xdp_l3_dynamic.sh` | Creates namespaces, veths, compiles/loads XDP, initializes routes |
| **Python CLI** | `userspace/xdpunk_cli.py` | User-space control plane; CRUD on routing table |
| **Package Config** | `userspace/pyproject.toml` | Installs `xdpunk-cli` command via setuptools |
| **Reset Script** | `scripts/reset.sh` | Cleans up all lab state (namespaces, BPF pins, temp files) |

### XDP Program Details

- **Input**: Intercepted packets from `data` buffer in `xdp_md` context
- **Processing**:
  - Validates Ethernet header
  - Extracts destination IP (handles both ARP and IPv4)
  - Queries `route_table` map with destination IP as key
  - Returns interface index if found, otherwise passes to kernel stack
- **Output**: Either `bpf_redirect(ifindex, 0)` to forward or `XDP_PASS` to pass up stack
- **License**: GPL (required for kernel eBPF)

### Map Structure

```c
BPF_MAP_TYPE_HASH {
  key:   __u32 (destination IPv4 in network byte order)
  value: __u32 (interface index / ifindex)
  max_entries: 256
}
```

The map is pinned to the BPF filesystem, allowing user-space (CLI) and kernel (XDP) to share state without IPC overhead.

### Setup Script Flow (`setup_xdp_l3_dynamic.sh`)

1. Creates 4 network namespaces (ns1, ns2, ns3, nssw)
2. Creates 3 veth pairs linking hosts to switch
3. Brings up all interfaces and assigns IP addresses
4. Compiles `xdp_forward_dynamic.c` to BPF bytecode
5. Loads compiled program and pins it + its maps
6. Attaches program to all switch interfaces
7. Populates route_table with initial IP→ifindex mappings
8. Displays setup summary and usage instructions

## Important Notes for Development

### Kernel Compilation & Testing

- The XDP program requires a Linux kernel built with eBPF/XDP support. Typically available in modern kernels (5.8+).
- All XDP operations must run as `root` or with `CAP_SYS_ADMIN` + `CAP_NET_ADMIN` capabilities.
- Changes to `xdp_forward_dynamic.c` require recompilation with `clang -target bpf` and reloading (full `setup` cycle or manual reload).

### Python CLI Development

- Uses `bcc` library (Python bindings to libbpf) for BPF map access.
- Handles network namespace context switching via ctypes/libc `setns()` syscall.
- IP address parsing: converts dotted-decimal to `u32` in network byte order using `socket.inet_aton()`.
- Interface resolution happens inside the target namespace (nssw by default) to ensure correct ifindex.

### Testing & Validation

- Connectivity tests use `ping` between namespaces: `ip netns exec ns1 ping 10.0.0.2`
- Packet capture: `ip netns exec ns3 tcpdump -i veth3h` to verify forwarding
- Map inspection: `sudo bpftool map dump pinned /sys/fs/bpf/xdp_fwd_maps/route_table`
- State cleanup critical between test runs; always run `reset.sh` before `setup_xdp_l3_dynamic.sh`

### Namespace & Network Context

- All XDP operations occur in the switch namespace (nssw)
- The CLI tool switches into the target namespace to resolve interface names to ifindex
- Routes are IP-based, not interface-name-based; ifindex is kernel-internal and namespace-specific

## Fase 2 — Firewall Stateless + Load Balancer de Links WAN

Implementation plan: `plano_firewall_loadbalancer.md`. Phase 1 artifacts remain intact as baselines.

### New Components

| Component | File(s) | Role |
|-----------|---------|------|
| **XDP FW+LB Program** | `xdp/xdp_fw_lb.c` | Pipeline: parse L2/L3/L4 → stateless firewall (5-tuple rules, first-match) → route_table hit = LAN redirect / miss = WAN load balancer (flow-hash or round-robin). All IPv4 redirects rewrite MACs (values stored in maps). |
| **CLI Package** | `userspace/xdpunk_cli/` (`cli.py`, `maps.py`, `netns.py`, `route.py`, `fw.py`, `lb.py`, `stats.py`) | Replaces the old single-file module. New groups: `fw`, `lb`, `stats`. `--legacy` flag operates the Phase 1 map (u32 value). |
| **Phase 2 Lab** | `scripts/setup_xdp_fw_lb.sh` | 6 namespaces: ns1/ns2 (LAN 10.0.0.0/24, fake gateway 10.0.0.254 via static neigh), nssw (XDP, `ip_forward=0`), nsp1/nsp2 (WAN providers, kernel forwarding), nsext ("internet", 192.0.2.10 on lo). |
| **Baseline Router** | `scripts/setup_baseline_router.sh [--fw-rules N] [--ecmp]` | Same topology without XDP: bridge + iptables FORWARD (+ br_netfilter) + kernel ECMP. Benchmark baseline. |
| **Benchmarks** | `experiments/run_fw_bench.sh`, `experiments/run_lb_bench.sh` | iperf3 JSON + BPF counters: FW XDP vs iptables (TCP Gbit/s, UDP-64B pps, N ∈ {0..64} rules); LB XDP vs ECMP (aggregate throughput, per-link distribution). |

### Phase 2 Key Facts

- BPF pins: program `/sys/fs/bpf/xdpunk_prog`, maps `/sys/fs/bpf/xdpunk/<name>` (separate from Phase 1 pins).
- Compile with `clang -O2 -g -target bpf -mcpu=v3` (round-robin uses atomic fetch-add, BPF ISA v3).
- Maps: `route_table` (value is now `route_entry` {ifindex, dmac, smac}), `fw_rules`/`fw_config`/`fw_stats`, `wan_links`/`lb_config`/`rr_state`/`wan_stats`, `global_stats`. Stats are PERCPU (CLI sums CPUs).
- C structs in `xdp_fw_lb.c` are mirrored in `userspace/xdpunk_cli/maps.py` — keep both in sync (no implicit padding).
- Control plane examples:
  - `xdpunk-cli fw add --prio 0 --src 10.0.0.1/32 --proto tcp --dport 5201 --action drop`
  - `xdpunk-cli lb link add 0 vethw1s --dmac <MAC vethw1p>` / `lb mode hash|rr` / `lb link disable 0` (failover)
  - `xdpunk-cli stats --reset` (between benchmark rounds)
- Docs: `docs/xdp_fw_lb.md`, `docs/setup_xdp_fw_lb.md`.
- The two labs must not run simultaneously (LAN namespace/veth names overlap); `scripts/reset.sh` cleans both.

