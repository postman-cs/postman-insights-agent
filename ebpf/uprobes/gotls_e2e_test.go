// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package uprobes

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
)

// TestGoTLSCaptureE2E is the end-to-end proof for Go crypto/tls capture. The
// test binary itself uses crypto/tls (via httptest.NewTLSServer and its
// client), so we attach the go_tls programs to /proc/self/exe, drive one HTTPS
// request, and assert that the decrypted request path and response body arrive
// on the go_events ringbuf.
//
// enforceAllowlist is false here: the uprobe is attached with a PID filter
// (link.UprobeOptions.PID), so the kernel already scopes firing to the target
// process — matching the production default (loader.Default() sets
// EnforcePIDAllowlist=false). The in-BPF allowlist is an optional second layer
// that keys on the init-namespace tgid; it applies under a DaemonSet's
// hostPID=true (agent-ns pid == init-ns pid) but not inside Docker Desktop's
// nested pid namespace, so it is intentionally not exercised by this test.
//
// Requirements: linux, -tags insights_bpf, root/CAP_BPF, and bpf2go artifacts.
// Runs inside build-scripts/dev-container.sh.
func TestGoTLSCaptureE2E(t *testing.T) {
	const marker = "hello-plaintext-9f3a"

	self := "/proc/self/exe"
	t.Logf("resolved runtime.g.goid offset = %d (published per-PID by AttachGoTLS)", goidOffset(self))

	l, err := loader.LoadGoTLS(loader.GoTLSMaxCaptureForTest(), false)
	if err != nil {
		t.Fatalf("LoadGoTLS: %v", err)
	}
	defer l.Close()

	mgr := NewGoManager(l)
	defer mgr.Close()

	pid := uint32(os.Getpid())
	if err := mgr.AttachGoTLS(pid, self); err != nil {
		t.Fatalf("AttachGoTLS: %v", err)
	}
	probes := mgr.ProbeCount(pid)
	t.Logf("attached %d go_tls uprobe links to pid=%d", probes, pid)
	if probes < 4 {
		t.Fatalf("expected >=4 probe links (2 entries + RET sites), got %d", probes)
	}

	rd, err := ringbuf.NewReader(l.EventsMap())
	if err != nil {
		t.Fatalf("ringbuf.NewReader: %v", err)
	}
	defer rd.Close()

	var (
		mu       sync.Mutex
		egress   strings.Builder
		ingress  strings.Builder
		evtCount int
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			rec, err := rd.Read()
			if err != nil {
				return
			}
			ev, err := events.Decode(rec.RawSample)
			if err != nil {
				continue
			}
			mu.Lock()
			evtCount++
			if ev.Direction == events.DirEgress {
				egress.Write(ev.Bytes())
			} else {
				ingress.Write(ev.Bytes())
			}
			mu.Unlock()
		}
	}()
	_ = ctx

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, marker+"\n")
	}))
	defer srv.Close()

	client := srv.Client()
	resp, err := client.Get(srv.URL + "/probe-path")
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), marker) {
		t.Fatalf("app-level body missing marker: %q", string(body))
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := strings.Contains(egress.String(), marker) || strings.Contains(ingress.String(), marker)
		mu.Unlock()
		if got {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	mu.Lock()
	eg, in, n := egress.String(), ingress.String(), evtCount
	mu.Unlock()

	emitted, _ := l.ReadCounter(loader.GoCounterEventsEmitted)
	missing, _ := l.ReadCounter(loader.GoCounterMissingStash)
	t.Logf("events on ringbuf=%d, bpf emitted counter=%d, missing_stash=%d", n, emitted, missing)
	t.Logf("captured egress bytes=%d ingress bytes=%d", len(eg), len(in))

	all := eg + "\x00" + in
	if !strings.Contains(all, marker) {
		t.Fatalf("decrypted plaintext marker %q not found in captured go_events\n--- egress(%d) ---\n%s\n--- ingress(%d) ---\n%s",
			marker, len(eg), truncate(eg, 512), len(in), truncate(in, 512))
	}
	if !strings.Contains(all, "/probe-path") {
		t.Errorf("expected request path /probe-path in captured plaintext (HTTP/1.1); "+
			"not fatal since HTTP/2 frames headers via HPACK. egress head: %q", truncate(eg, 256))
	}
	if emitted == 0 {
		t.Errorf("BPF events-emitted counter is 0 despite ringbuf activity")
	}
	t.Logf("PASS: captured decrypted Go crypto/tls plaintext containing %q", marker)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "...(truncated)"
	}
	return s
}
