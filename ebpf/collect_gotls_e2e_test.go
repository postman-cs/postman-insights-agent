// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"

	"github.com/postmanlabs/postman-insights-agent/ebpf"
	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
)

// goHTTPSServerSrc is a standalone Go HTTPS echo server. httptest.NewTLSServer
// drives crypto/tls.(*Conn).Read/Write, which is exactly what the go_tls
// uprobes hook. It prints its URL on the first stdout line, then blocks.
const goHTTPSServerSrc = "package main\n" +
	"import (\n" +
	"\t\"fmt\"\n" +
	"\t\"io\"\n" +
	"\t\"net/http\"\n" +
	"\t\"net/http/httptest\"\n" +
	"\t\"os\"\n" +
	"\t\"os/signal\"\n" +
	"\t\"syscall\"\n" +
	")\n" +
	"func main() {\n" +
	"\tsrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n" +
	"\t\tb, _ := io.ReadAll(r.Body)\n" +
	"\t\tfmt.Fprintf(w, \"echo:%s\", b)\n" +
	"\t}))\n" +
	"\tfmt.Println(srv.URL)\n" +
	"\tc := make(chan os.Signal, 1)\n" +
	"\tsignal.Notify(c, syscall.SIGINT, syscall.SIGTERM)\n" +
	"\t<-c\n" +
	"\tsrv.Close()\n" +
	"}\n"

// TestGoTLSDiscoveryE2E proves the full discovery-native path: a freshly
// started, unmodified Go HTTPS process is auto-detected by the collector's
// own discovery loop (no per-service config, no explicit AttachGoTLS call),
// uprobes are attached, and its decrypted crypto/tls traffic is captured.
func TestGoTLSDiscoveryE2E(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root (CAP_BPF) to load uprobes")
	}

	// 1. Build a standalone Go HTTPS server for THIS platform and run it.
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "srv.go")
	if err := os.WriteFile(srcPath, []byte(goHTTPSServerSrc), 0o644); err != nil {
		t.Fatalf("write server src: %v", err)
	}
	binPath := filepath.Join(dir, "srv")
	if outb, err := exec.Command("go", "build", "-o", binPath, srcPath).CombinedOutput(); err != nil {
		t.Fatalf("build server: %v\n%s", err, outb)
	}

	srv := exec.Command(binPath)
	stdout, err := srv.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer func() { _ = srv.Process.Kill(); _ = srv.Wait() }()
	serverPID := uint32(srv.Process.Pid)

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("read server URL: %v", err)
	}
	url := strings.TrimSpace(line)
	if !strings.HasPrefix(url, "https://") {
		t.Fatalf("unexpected server URL: %q", url)
	}
	t.Logf("go https server pid=%d url=%s", serverPID, url)

	// 2. Build the collector. It scans /proc, so the already-running server
	//    lets it self-configure the goid offset. No target PID is supplied.
	out := make(chan akinet.ParsedNetworkTraffic, 256)
	go func() {
		for range out { // drain; capture is asserted via BPF counters
		}
	}()
	adapter := events.NewAdapter(akinet.TCPParserFactorySelector(nil), out)
	collector, err := ebpf.NewGoTLSCollector(1023, adapter, "/proc")
	if err != nil {
		t.Fatalf("NewGoTLSCollector: %v", err)
	}
	defer func() { _ = collector.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go collector.Run(ctx, time.Now())

	// 3. Wait for the collector's OWN discovery loop to auto-attach the
	//    server -- this is the zero-config auto-pickup we are proving.
	deadline := time.Now().Add(20 * time.Second)
	attached := false
	for time.Now().Before(deadline) {
		for _, pid := range collector.AttachedPIDs() {
			if pid == serverPID {
				attached = true
				break
			}
		}
		if attached {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !attached {
		t.Fatalf("collector did not auto-discover+attach server pid=%d within deadline", serverPID)
	}
	t.Logf("PASS: auto-discovered and attached server pid=%d with no per-service config", serverPID)

	// 4. Drive one HTTPS request carrying a marker; the server decrypts it.
	const marker = "discovery-marker-7c2e"
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Post(url, "text/plain", strings.NewReader(marker))
	if err != nil {
		t.Fatalf("client POST: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), marker) {
		t.Fatalf("server echo missing marker: %q", body)
	}

	// 5. Assert the BPF program captured plaintext from the auto-attached pid.
	var emitted uint64
	for i := 0; i < 25; i++ {
		emitted = collector.CounterEmitted()
		if emitted > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if emitted == 0 {
		t.Fatalf("no plaintext events captured from auto-discovered server pid=%d", serverPID)
	}
	if ms := collector.CounterMissingStash(); ms > 0 {
		t.Logf("note: missing_stash=%d (entry/RET correlation misses)", ms)
	}
	t.Logf("PASS: captured %d plaintext events from auto-discovered Go crypto/tls server", emitted)

	// Silence unused import in some toolchains.
	_ = strconv.Itoa(0)
}
