# `ebpf/` — HTTPS capture subsystem

This package adds **HTTPS traffic capture** to the Postman Insights Agent via eBPF uprobes on userspace TLS libraries. The full design lives in [`docs/https-capture-design.md`](../docs/https-capture-design.md).

## Current status

The libssl uprobe → ringbuf → resolver → adapter → akinet pipeline is
end-to-end functional on Linux 5.8+, wired into production via
`apidump --enable-https-capture` and the `kube inject --enable-https-capture`
DaemonSet path. Java TLS capture (JVM ioctl bridge) and a mutating admission
webhook that injects the agent + java-agent are also landed.

| Component | Status |
|---|---|
| BPF C source (`programs/libssl.bpf.c`) | ✅ Compiles, loads past verifier on kernel 6.12 |
| BPF C source (`programs/java_tls.bpf.c`) | ✅ Kprobe on the JVM ioctl bridge |
| Go loader (`loader/`) | ✅ bpf2go bindings (arm64 committed; amd64 generated in the eBPF build container / CI) |
| Ringbuf reader (`events/reader_linux.go`) | ✅ |
| Decoder (`events/decode.go`) | ✅ |
| Adapter to akinet (`events/adapter.go`) | ✅ `Parse()` loop with pipelining, chunked delivery, 64 KiB cap |
| fd → 4-tuple resolution (`events/resolver.go`) | ✅ Per-PID `/proc/<pid>/net/tcp{,6}` cache + 5 ms proactive pre-resolve loop |
| Process discovery (`discovery/`) | ✅ `/proc` scan/watch + CRI/Kube namespace resolver (cgroup-ns-inode bridging) |
| Uprobe attachment (`uprobes/`) | ✅ Dynamic libssl (OpenSSL 1.1 & 3.x); static BoringSSL in `node` (Node 20+) |
| Top-level `Collect()` | ✅ |
| Spike command (`cmd/internal/apidump-ebpf/`) | ✅ Validated against curl, Python `requests`, Node `https.get` |
| `apidump --enable-https-capture` integration | ✅ Dedicated collector chain reusing data_masks / rate_limit / backend_collector |
| `kube inject --enable-https-capture` | ✅ Adds CAP_BPF + CAP_PERFMON, hostPID, hostPath mounts to the sidecar |
| Mutating admission webhook + Helm chart | ✅ `cmd/internal/kube-webhook/` + `charts/postman-insights-webhook/` |
| cBPF port-443 exclusion | ✅ `--https-cbpf-exclude-port` (default 443) |
| Sampling layer 1 (body truncation) | ✅ |
| Sampling layer 2 (per-PID rate cap) | ✅ `ratecap_linux.go` |
| Sampling layer 5 (CPU thermostat) | ✅ `thermostat_linux.go` |
| Telemetry counters | ✅ `httpsTelemetryWorker` emits `ebpf_capture_stats` every 30 s |
| **Go `crypto/tls` capture (`programs/go_tls.bpf.c`)** | ❌ Not started — see "What's left" |
| amd64 bpf2go objects as a release artifact | 🟡 Built in the eBPF dev container; not yet a committed release-image artifact |
| End-to-end on a kind cluster | 🟡 Manifests + scripts present (`docs/kind-e2e-demo-presentation.md`); needs a Linux/DinD runner |

Phase result write-ups live in [`docs/phases/`](../docs/phases/) and
[`docs/progress.md`](../docs/progress.md).

## Build tags

The eBPF code paths are gated behind two conditions:

- `linux` — eBPF is a Linux kernel facility.
- `insights_bpf` — opt-in build tag that requires `bpf2go` to have run.

| Tag combination | Behaviour |
|---|---|
| Default (`go build .`) | Stubs compile everywhere. `apidump-ebpf` prints "not compiled in". |
| `-tags insights_bpf` on Linux | Real eBPF code. Requires `bpf2go` artifacts to be present. |
| `-tags insights_bpf` on macOS | Build fails (loader_linux.go won't match). Use Linux dev VM or container. |

## How to actually build & run

### On macOS (Apple Silicon or Intel) via Docker Desktop

```bash
make dev-build          # one-time: build the dev container image
make dev-shell          # open a shell inside it (repo bind-mounted, --pid=host)

# Inside the shell:
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/programs/vmlinux.h
go generate ./ebpf/loader/...                                     # runs bpf2go (needs clang + vmlinux.h)
go build -tags insights_bpf -o bin/postman-insights-agent .
./bin/postman-insights-agent apidump-ebpf --duration 60s          # spike
# or for the production path:
./bin/postman-insights-agent apidump --enable-https-capture --project ...
```

### On a Linux host with `clang ≥ 14`, `llvm-strip`, `bpftool`, `libbpf-dev`

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/programs/vmlinux.h
go generate ./ebpf/loader/...
go build -tags insights_bpf -o bin/postman-insights-agent .
sudo ./bin/postman-insights-agent apidump-ebpf --duration 60s
```

In another terminal, generate HTTPS traffic:

```bash
curl -sv https://example.com/ > /dev/null
```

Expected output in the spike: `REQ method=GET url=...` and `RESP status=200`.

## Package layout

```
ebpf/
├── README.md                    you are here
├── collect.go                   exported ErrUnsupported (all builds)
├── collect_linux.go             Collect() — top-level pipeline (linux+insights_bpf)
├── collect_stub.go              Collect() — no-op (other builds)
├── clock_linux.go               CLOCK_BOOTTIME helper for event timestamps
│
├── programs/                    BPF C sources, compiled to .o by bpf2go
│   ├── README.md
│   ├── event.h                  shared struct ssl_event {…}
│   ├── libssl.bpf.c             uprobes for SSL_read/SSL_write/*_ex
│   └── java_tls.bpf.c           kprobe on the JVM ioctl bridge
│
├── loader/                      cilium/ebpf loader + bpf2go invocation
│   ├── loader.go                package doc
│   ├── loader_linux.go          real Loader (linux+insights_bpf)
│   ├── loader_stub.go           no-op Loader (other builds)
│   └── config.go                load-time knobs
│
├── events/                      ringbuf reader + Go event types + adapter
│   ├── event.go                 SSLEvent + FlowKey
│   ├── decode.go                ringbuf-bytes → SSLEvent
│   ├── reader_linux.go          ringbuf.Reader wrapper (linux+insights_bpf)
│   ├── reader_stub.go           no-op (other builds)
│   └── adapter.go               feeds bytes into akinet parsers (PHASE 2 wiring)
│
├── uprobes/                     symbol resolution + uprobe attach
│   ├── openssl.go               /proc/<pid>/maps walker (all builds)
│   ├── attach_linux.go          Manager.AttachLibSSL (linux+insights_bpf)
│   └── attach_stub.go           no-op (other builds)
│
└── discovery/                   target-PID enumeration
    ├── proc.go                  scan + watch /proc for PIDs with libssl loaded
    └── kube_linux.go            CRI + cgroup-ns-inode → k8s-namespace resolver
```

## What's left

1. **Go `crypto/tls` capture (`programs/go_tls.bpf.c`).** The one substantive
   functional gap, and the highest-value item for a Go-heavy fleet. Go
   statically links its own TLS stack (no libssl to hook), and the Go runtime
   moves goroutine stacks, so naive uretprobes are unreliable. The proven
   approach (Pixie / Beyla / OBI) attaches uprobes on
   `crypto/tls.(*Conn).Read`/`Write` and locates return sites by scanning the
   function body for RET instructions, reading arguments/results per Go's
   register ABI. Must be built, verifier-checked, and runtime-validated inside
   the eBPF dev container (`build-scripts/dev-container.sh`).
2. **amd64 BPF objects as a release artifact.** bpf2go emits arm64 + amd64,
   but only arm64 objects are committed; CI should generate amd64 in the eBPF
   container and embed both in the release image.
3. **End-to-end kind-cluster test.** Manifests + scripts exist
   (`docs/kind-e2e-demo-presentation.md`); needs a Linux or Docker-in-Docker
   runner to exercise the namespace-filtering exit criterion.
