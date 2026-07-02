package proxy_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/buffer_pool"
	"github.com/postmanlabs/postman-insights-agent/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingCollector struct {
	mu      sync.Mutex
	traffic []akinet.ParsedNetworkTraffic
}

func (c *recordingCollector) Process(t akinet.ParsedNetworkTraffic) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.traffic = append(c.traffic, t)
	return nil
}

func (c *recordingCollector) Close() error { return nil }

func (c *recordingCollector) snapshot() []akinet.ParsedNetworkTraffic {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]akinet.ParsedNetworkTraffic{}, c.traffic...)
}

// Waits until the collector has seen n traffic entries.
func (c *recordingCollector) await(t *testing.T, n int) []akinet.ParsedNetworkTraffic {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.snapshot(); len(got) >= n {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := c.snapshot()
	require.GreaterOrEqual(t, len(got), n, "timed out waiting for %d collected records, have %d", n, len(got))
	return got
}

func startProxy(t *testing.T, args proxy.Args) (*proxy.Proxy, *recordingCollector) {
	t.Helper()
	pool, err := buffer_pool.MakeBufferPool(16*1024*1024, 4*1024)
	require.NoError(t, err)
	rec := &recordingCollector{}
	if args.ListenAddr == "" {
		args.ListenAddr = "127.0.0.1:0"
	}
	p, err := proxy.New(args, rec, pool)
	require.NoError(t, err)
	stop := make(chan struct{})
	go func() {
		if err := p.Serve(stop); err != nil {
			t.Errorf("proxy serve error: %v", err)
		}
	}()
	t.Cleanup(func() { close(stop) })
	return p, rec
}

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	require.NoError(t, err)
	return u
}

func pairUp(t *testing.T, traffic []akinet.ParsedNetworkTraffic) (map[string]akinet.HTTPRequest, map[string]akinet.HTTPResponse) {
	t.Helper()
	reqs := map[string]akinet.HTTPRequest{}
	resps := map[string]akinet.HTTPResponse{}
	for _, tr := range traffic {
		switch c := tr.Content.(type) {
		case akinet.HTTPRequest:
			key := c.StreamID.String() + "/" + fmt.Sprint(c.Seq)
			_, dup := reqs[key]
			require.False(t, dup, "duplicate request stream/seq %s", key)
			reqs[key] = c
		case akinet.HTTPResponse:
			key := c.StreamID.String() + "/" + fmt.Sprint(c.Seq)
			_, dup := resps[key]
			require.False(t, dup, "duplicate response stream/seq %s", key)
			resps[key] = c
		default:
			t.Fatalf("unexpected content type %T", tr.Content)
		}
	}
	return reqs, resps
}

// The core motivating scenario: the upstream service only speaks HTTPS. The
// passive pcap path sees only TLS records here; the proxy must produce full
// request/response witnesses.
func TestCapturesHTTPSUpstream(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "{\"received\": %d, \"path\": %q}", len(body), r.URL.Path)
	}))
	defer upstream.Close()

	p, rec := startProxy(t, proxy.Args{
		Upstream:            mustParseURL(t, upstream.URL),
		UpstreamTLSInsecure: true,
	})

	reqBody := "{\"name\": \"example\", \"tier\": 1}"
	req, err := http.NewRequest("POST", "http://"+p.Addr().String()+"/v1/users?verbose=true", strings.NewReader(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "test-key-123")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	traffic := rec.await(t, 2)
	require.Len(t, traffic, 2)
	reqs, resps := pairUp(t, traffic)
	require.Len(t, reqs, 1)
	require.Len(t, resps, 1)

	for key, gotReq := range reqs {
		gotResp, ok := resps[key]
		require.True(t, ok, "request %s has no paired response", key)

		assert.Equal(t, "POST", gotReq.Method)
		assert.Equal(t, "/v1/users", gotReq.URL.Path)
		assert.Equal(t, "verbose=true", gotReq.URL.RawQuery)
		assert.Equal(t, "test-key-123", gotReq.Header.Get("X-Api-Key"))
		assert.Equal(t, reqBody, gotReq.Body.String())

		assert.Equal(t, http.StatusCreated, gotResp.StatusCode)
		assert.Equal(t, "application/json", gotResp.Header.Get("Content-Type"))
		assert.Equal(t, string(respBody), gotResp.Body.String())

		var parsed map[string]any
		require.NoError(t, json.Unmarshal([]byte(gotResp.Body.String()), &parsed))
		assert.Equal(t, float64(len(reqBody)), parsed["received"])
	}

	// Traffic metadata: request goes client -> proxy, response the reverse.
	for _, tr := range traffic {
		if _, isReq := tr.Content.(akinet.HTTPRequest); isReq {
			assert.Equal(t, proxy.InterfaceName, tr.Interface)
			assert.NotZero(t, tr.DstPort)
		}
		assert.False(t, tr.ObservationTime.IsZero())
		assert.False(t, tr.FinalPacketTime.Before(tr.ObservationTime))
	}
}

// The proxy itself terminates TLS for clients, covering the case where
// callers require HTTPS all the way to the pod.
func TestServesTLSListener(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "plain upstream ok")
	}))
	defer upstream.Close()

	certFile, keyFile := writeSelfSignedCert(t)
	p, rec := startProxy(t, proxy.Args{
		Upstream:    mustParseURL(t, upstream.URL),
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	})

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get("https://" + p.Addr().String() + "/health/tls")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "plain upstream ok", string(body))

	traffic := rec.await(t, 2)
	reqs, resps := pairUp(t, traffic)
	require.Len(t, reqs, 1)
	require.Len(t, resps, 1)
	for _, gotReq := range reqs {
		assert.Equal(t, "GET", gotReq.Method)
		assert.Equal(t, "/health/tls", gotReq.URL.Path)
	}
}

// An unreachable upstream should still record the request and the 502 the
// client actually received.
func TestUpstreamFailureRecords502(t *testing.T) {
	// Grab a port that is guaranteed closed.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	deadAddr := l.Addr().String()
	l.Close()

	p, rec := startProxy(t, proxy.Args{
		Upstream: mustParseURL(t, "http://"+deadAddr),
	})

	resp, err := http.Get("http://" + p.Addr().String() + "/v1/orders")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)

	traffic := rec.await(t, 2)
	reqs, resps := pairUp(t, traffic)
	require.Len(t, reqs, 1)
	require.Len(t, resps, 1)
	for key, gotReq := range reqs {
		assert.Equal(t, "/v1/orders", gotReq.URL.Path)
		gotResp, ok := resps[key]
		require.True(t, ok)
		assert.Equal(t, http.StatusBadGateway, gotResp.StatusCode)
	}
}

func TestConcurrentExchangesPairCorrectly(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "resp:"+r.URL.Path)
	}))
	defer upstream.Close()

	p, rec := startProxy(t, proxy.Args{Upstream: mustParseURL(t, upstream.URL)})

	const n = 25
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := http.Get(fmt.Sprintf("http://%s/v1/items/%d", p.Addr().String(), i))
			if err != nil {
				t.Errorf("request %d failed: %v", i, err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}(i)
	}
	wg.Wait()

	traffic := rec.await(t, 2*n)
	reqs, resps := pairUp(t, traffic)
	require.Len(t, reqs, n)
	require.Len(t, resps, n)

	seenPaths := map[string]bool{}
	for key, gotReq := range reqs {
		gotResp, ok := resps[key]
		require.True(t, ok, "request %s has no paired response", key)
		assert.Equal(t, "resp:"+gotReq.URL.Path, gotResp.Body.String())
		assert.False(t, seenPaths[gotReq.URL.Path], "path %s captured twice", gotReq.URL.Path)
		seenPaths[gotReq.URL.Path] = true
	}
}

// Oversized bodies are streamed through untouched but excluded from capture.
func TestOversizedBodyExcludedFromWitness(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprintf(w, "got %d bytes", n)
	}))
	defer upstream.Close()

	p, rec := startProxy(t, proxy.Args{
		Upstream:              mustParseURL(t, upstream.URL),
		MaxCapturedBody_bytes: 1024,
	})

	big := bytes.Repeat([]byte("x"), 64*1024)
	resp, err := http.Post("http://"+p.Addr().String()+"/v1/upload", "application/octet-stream", bytes.NewReader(big))
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	assert.Equal(t, fmt.Sprintf("got %d bytes", len(big)), string(body))

	traffic := rec.await(t, 2)
	reqs, resps := pairUp(t, traffic)
	require.Len(t, reqs, 1)
	for _, gotReq := range reqs {
		assert.Zero(t, gotReq.Body.Len(), "oversized request body should be excluded")
	}
	for _, gotResp := range resps {
		assert.Equal(t, fmt.Sprintf("got %d bytes", len(big)), gotResp.Body.String())
	}
}

func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600))
	return certFile, keyFile
}
