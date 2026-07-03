// SPDX-License-Identifier: Apache-2.0

package uprobes

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// buildELF cross-compiles src into a linux/arm64 ELF (regardless of the host
// OS) so isGoTLSBinary -- which parses ELF -- can be exercised on macOS and
// Linux alike. The binary is only parsed, never run.
func buildELF(t *testing.T, src string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(srcPath, []byte(src), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	binPath := filepath.Join(dir, "prog")
	cmd := exec.Command("go", "build", "-o", binPath, srcPath)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
	if outb, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cross-compile unavailable: %v\n%s", err, outb)
	}
	return binPath
}

// A real HTTPS server (or client) actually calls crypto/tls.(*Conn).Write and
// Read, so the linker keeps those named methods -- and the detector must
// classify it as a Go TLS target. A bare method-expression reference is not
// enough: the linker wraps it and still eliminates the named method, which is
// why this uses the httptest form that exercises the full call path, matching
// how production Go HTTPS binaries retain the symbols.
func TestIsGoTLSBinary_DetectsCryptoTLS(t *testing.T) {
	const src = "package main\n" +
		"import (\n\t\"fmt\"\n\t\"net/http\"\n\t\"net/http/httptest\"\n)\n" +
		"func main() {\n" +
		"\ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))\n" +
		"\tfmt.Println(s.URL)\n" +
		"\ts.Close()\n" +
		"}\n"
	bin := buildELF(t, src)
	if !isGoTLSBinary(bin) {
		t.Errorf("expected a Go binary linking crypto/tls to be detected")
	}
}

// A Go program that does not link crypto/tls must NOT be classified as a Go
// TLS target (no false positives on arbitrary Go workloads).
func TestIsGoTLSBinary_RejectsNonTLSGo(t *testing.T) {
	bin := buildELF(t, "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"hi\") }\n")
	if isGoTLSBinary(bin) {
		t.Errorf("expected a Go binary without crypto/tls to be rejected")
	}
}

// A non-Go file must be rejected without panicking.
func TestIsGoTLSBinary_RejectsNonGo(t *testing.T) {
	if isGoTLSBinary("/nonexistent/path/xyz") {
		t.Errorf("expected nonexistent path to be rejected")
	}
}
