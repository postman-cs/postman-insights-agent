// SPDX-License-Identifier: Apache-2.0
//
// go_tls — HTTPS capture for statically-linked Go binaries.
//
// Go compiles crypto/tls into every executable, so there is no libssl symbol
// to hook (unlike libssl.bpf.c) and no ioctl bridge (unlike java_tls.bpf.c).
// Instead we uprobe the standard-library TLS entry points directly:
//
//     crypto/tls.(*Conn).Write(b []byte) (int, error)   -> DIR_EGRESS
//     crypto/tls.(*Conn).Read(b []byte)  (int, error)   -> DIR_INGRESS
//
// Two Go-specific constraints shape this program (prior art: Pixie
// go_tls_trace.c, Grafana Beyla / OpenTelemetry OBI gotracer, and
// Speedscale's RET-scan write-up):
//
//   1. NO URETPROBES. Go moves goroutine stacks at runtime, which invalidates
//      the uretprobe trampoline's saved return address and crashes the target
//      (golang/go#22008). The Go loader therefore disassembles each function,
//      finds every RET offset, and attaches the *_ret programs below as plain
//      uprobes at those offsets — mimicking a uretprobe safely.
//
//   2. REGISTER ABI (Go 1.17+). Args and results travel in registers, and the
//      register file differs between entry and return. We read args at entry,
//      stash them keyed by (tgid, goid), and read the result count at the RET
//      site. The goroutine id is stable across the call, so it survives.
//
// Register conventions (Go internal ABI):
//   amd64: integer args/results RAX,RBX,RCX,RDI,RSI,R8,R9,R10,R11; g in R14.
//   arm64: integer args/results R0..R15;                            g in R28.
//   A method receiver is arg0; a []byte occupies 3 regs (ptr,len,cap).
//   Write(c,b): conn=reg0, buf.ptr=reg1, buf.len=reg2. Result n=reg0 at RET.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "event.h"

char LICENSE[] SEC("license") = "GPL";

// -----------------------------------------------------------------------------
// Loader-set constants (.rodata / .data)
// -----------------------------------------------------------------------------

// 0 = trace all PIDs; 1 = only PIDs present in go_target_pids.
volatile const __u32 go_enforce_pid_allowlist = 0;

// Byte offset of runtime.g.goid within the g struct. Version-dependent; the
// Go loader resolves it (version table or DWARF) and rewrites it at load time.
// 0 means "unknown" — we then fall back to bpf_get_current_pid_tgid()'s tid as
// a coarse correlation key (correct for the common one-goroutine-per-call
// case; a real goid is preferred once resolved).
volatile const __u64 go_goid_offset = 0;

// Runtime-adjustable capture cap (thermostat can lower it). The loader MUST
// keep this <= MAX_EVENT_PAYLOAD-1 so the mask in go_tls_ret is a no-op; the
// mask (not this value) is what proves the read length bounded to the verifier.
__u32 go_max_capture_bytes = MAX_EVENT_PAYLOAD - 1;

// -----------------------------------------------------------------------------
// Maps
// -----------------------------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);
} go_events SEC(".maps");

// PID allowlist (same shape/semantics as libssl target_pids).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);   // tgid
    __type(value, __u8);
} go_target_pids SEC(".maps");

// Entry->return correlation. Keyed by (tgid, goid); value carries the args we
// need at the RET site.
struct go_op_key {
    __u32 tgid;
    __u32 _pad;
    __u64 goid;
};

struct go_op_args {
    __u64 conn_ptr;   // *crypto/tls.Conn — opaque connection id (ssl_ctx)
    __u64 buf_ptr;    // b.ptr  (plaintext buffer)
    __u64 buf_len;    // b.len  (buffer capacity handed to Read/Write)
    __u8  direction;  // DIR_EGRESS (Write) / DIR_INGRESS (Read)
    __u8  _pad[7];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct go_op_key);
    __type(value, struct go_op_args);
} active_go_ops SEC(".maps");

// Diagnostic counters (mirrors libssl indices where they overlap):
//   0 = events emitted   1 = ringbuf-full drops   2 = arg/read failures
//   3 = goid-read failures  4 = missing-stash at return
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} go_counters SEC(".maps");

static __always_inline void go_counter_inc(__u32 idx, __u64 by) {
    __u64 *v = bpf_map_lookup_elem(&go_counters, &idx);
    if (v) {
        *v += by;
    }
}

static __always_inline int go_pid_allowed(__u32 tgid) {
    if (!go_enforce_pid_allowlist) {
        return 1;
    }
    return bpf_map_lookup_elem(&go_target_pids, &tgid) != NULL;
}

// -----------------------------------------------------------------------------
// Register ABI helpers
// -----------------------------------------------------------------------------

// Go's internal ABI does NOT match the SysV/pt_regs PARM macros, so we read the
// raw registers in Go-ABI order explicitly.
#if defined(__TARGET_ARCH_x86) || defined(bpf_target_x86)
static __always_inline __u64 go_reg(struct pt_regs *ctx, int n) {
    switch (n) {
        case 0: return ctx->ax;
        case 1: return ctx->bx;
        case 2: return ctx->cx;
        case 3: return ctx->di;
        case 4: return ctx->si;
        case 5: return ctx->r8;
        case 6: return ctx->r9;
        case 7: return ctx->r10;
        case 8: return ctx->r11;
        default: return 0;
    }
}
static __always_inline __u64 go_g_ptr(struct pt_regs *ctx) { return ctx->r14; }
#elif defined(__TARGET_ARCH_arm64) || defined(bpf_target_arm64)
static __always_inline __u64 go_reg(struct pt_regs *ctx, int n) {
    if (n < 0 || n > 15) return 0;
    return ctx->regs[n];
}
static __always_inline __u64 go_g_ptr(struct pt_regs *ctx) { return ctx->regs[28]; }
#else
#error "go_tls: unsupported target architecture"
#endif

// Resolve the current goroutine id. Returns 0 if unknown.
static __always_inline __u64 go_goid(struct pt_regs *ctx) {
    if (go_goid_offset == 0) {
        return 0;
    }
    __u64 g = go_g_ptr(ctx);
    if (!g) {
        return 0;
    }
    __u64 goid = 0;
    if (bpf_probe_read_user(&goid, sizeof(goid), (void *)(g + go_goid_offset)) != 0) {
        return 0;
    }
    return goid;
}

static __always_inline void go_make_key(struct go_op_key *k, __u32 tgid,
                                        struct pt_regs *ctx) {
    __builtin_memset(k, 0, sizeof(*k));
    k->tgid = tgid;
    __u64 goid = go_goid(ctx);
    // Fall back to the OS tid when the goid offset is unknown. Correct for the
    // overwhelmingly-common single-goroutine-per-call case.
    k->goid = goid ? goid : (bpf_get_current_pid_tgid() & 0xffffffff);
}

// -----------------------------------------------------------------------------
// Entry: stash (conn_ptr, buf_ptr, buf_len) keyed by (tgid, goid)
// -----------------------------------------------------------------------------

static __always_inline int go_tls_entry(struct pt_regs *ctx, __u8 direction) {
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (!go_pid_allowed(tgid)) {
        return 0;
    }

    struct go_op_key key;
    go_make_key(&key, tgid, ctx);

    struct go_op_args args = {};
    args.conn_ptr  = go_reg(ctx, 0);   // receiver c *Conn
    args.buf_ptr   = go_reg(ctx, 1);   // b.ptr
    args.buf_len   = go_reg(ctx, 2);   // b.len
    args.direction = direction;

    if (!args.conn_ptr || !args.buf_ptr) {
        go_counter_inc(2, 1);
        return 0;
    }

    bpf_map_update_elem(&active_go_ops, &key, &args, BPF_ANY);
    return 0;
}

SEC("uprobe/go_tls_write_entry")
int go_tls_write_entry(struct pt_regs *ctx) {
    return go_tls_entry(ctx, DIR_EGRESS);
}

SEC("uprobe/go_tls_read_entry")
int go_tls_read_entry(struct pt_regs *ctx) {
    return go_tls_entry(ctx, DIR_INGRESS);
}

// -----------------------------------------------------------------------------
// Return (attached at each RET offset, NOT a uretprobe): read n, emit plaintext
// -----------------------------------------------------------------------------

static __always_inline int go_tls_ret(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;

    struct go_op_key key;
    go_make_key(&key, tgid, ctx);

    struct go_op_args *args = bpf_map_lookup_elem(&active_go_ops, &key);
    if (!args) {
        go_counter_inc(4, 1);
        return 0;
    }

    // First result register holds n (bytes read/written). Negative/zero -> skip.
    __s64 n = (__s64)go_reg(ctx, 0);
    if (n <= 0) {
        bpf_map_delete_elem(&active_go_ops, &key);
        return 0;
    }

    __u32 to_copy = (__u32)n;
    if (to_copy > go_max_capture_bytes) {
        to_copy = go_max_capture_bytes;
    }
    // The mask is the ONLY thing that bounds the read length for the verifier.
    // We deliberately do NOT add an "if (to_copy > N)" clamp: -O2 would then
    // prove to_copy small, drop the mask, and feed the unbounded 64-bit return
    // register straight into bpf_probe_read_user (verifier rejects that as
    // "R2 unbounded memory access"). Because go_max_capture_bytes lives in
    // .data (verifier-unbounded), the compiler cannot prove to_copy small and
    // must keep the mask, which pins umax to MAX_EVENT_PAYLOAD-1. The loader
    // keeps the cap <= MAX_EVENT_PAYLOAD-1 so the mask never truncates.
    to_copy &= (MAX_EVENT_PAYLOAD - 1);

    struct ssl_event *e = bpf_ringbuf_reserve(&go_events, sizeof(*e), 0);
    if (!e) {
        go_counter_inc(1, 1);
        bpf_map_delete_elem(&active_go_ops, &key);
        return 0;
    }

    e->ts_ns        = bpf_ktime_get_ns();
    e->pid          = pid_tgid >> 32;
    e->tid          = (__u32)pid_tgid;
    e->ssl_ctx      = args->conn_ptr;
    e->len_total    = (__u32)n;
    e->len_captured = to_copy;
    e->fd           = -1;               // enrichment via conn->netFD is future work
    e->direction    = args->direction;
    __builtin_memset(e->_pad, 0, sizeof(e->_pad));

    if (bpf_probe_read_user(e->payload, to_copy, (void *)args->buf_ptr) != 0) {
        go_counter_inc(2, 1);
        bpf_ringbuf_discard(e, 0);
        bpf_map_delete_elem(&active_go_ops, &key);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    go_counter_inc(0, 1);
    bpf_map_delete_elem(&active_go_ops, &key);
    return 0;
}

SEC("uprobe/go_tls_write_ret")
int go_tls_write_ret(struct pt_regs *ctx) {
    return go_tls_ret(ctx);
}

SEC("uprobe/go_tls_read_ret")
int go_tls_read_ret(struct pt_regs *ctx) {
    return go_tls_ret(ctx);
}
