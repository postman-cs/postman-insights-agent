package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/buffer_pool"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/trace"
)

// The interface name reported in ParsedNetworkTraffic and used in error
// reporting alongside real capture interfaces.
const InterfaceName = "reverse-proxy"

// Bodies larger than this are streamed to their destination unmodified but
// excluded from the witness, mirroring the back-end collector's
// maximum-witness-size drop.
const DefaultMaxCapturedBody_bytes = 1024 * 1024

type Args struct {
	// Address to accept application traffic on, e.g. ":16789".
	ListenAddr string

	// Base URL of the service to forward traffic to, e.g.
	// "https://127.0.0.1:8443".
	Upstream *url.URL

	// PEM certificate and key used to terminate TLS. If unset, the listener
	// speaks plaintext HTTP.
	TLSCertFile string
	TLSKeyFile  string

	// Skip verification of the upstream's TLS certificate, e.g. for
	// self-signed in-cluster certificates.
	UpstreamTLSInsecure bool

	MaxCapturedBody_bytes int
}

// A TLS-terminating reverse proxy that emits each HTTP exchange it forwards
// into a trace.Collector. This provides visibility into HTTPS (and HTTP/2)
// traffic that the passive pcap capture path cannot parse: the proxy is an
// endpoint of the TLS session, so it sees plaintext regardless of how the
// surrounding network is encrypted.
type Proxy struct {
	args      Args
	collector trace.Collector
	pool      buffer_pool.BufferPool

	listener   net.Listener
	server     *http.Server
	reverse    *httputil.ReverseProxy
	listenIP   net.IP
	listenPort int
	maxBody    int

	// Serializes collector.Process calls; exchanges complete on arbitrary
	// server goroutines, but collectors expect single-threaded input from
	// each capture source.
	collectorMu sync.Mutex
}

func New(args Args, collector trace.Collector, pool buffer_pool.BufferPool) (*Proxy, error) {
	if args.Upstream == nil {
		return nil, errors.New("reverse proxy requires an upstream URL")
	}
	switch args.Upstream.Scheme {
	case "http", "https":
	default:
		return nil, errors.Errorf("unsupported upstream scheme %q", args.Upstream.Scheme)
	}
	if (args.TLSCertFile == "") != (args.TLSKeyFile == "") {
		return nil, errors.New("reverse proxy TLS certificate and key must be provided together")
	}

	listener, err := net.Listen("tcp", args.ListenAddr)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to listen on %s", args.ListenAddr)
	}

	maxBody := args.MaxCapturedBody_bytes
	if maxBody <= 0 {
		maxBody = DefaultMaxCapturedBody_bytes
	}

	p := &Proxy{
		args:      args,
		collector: collector,
		pool:      pool,
		listener:  listener,
		maxBody:   maxBody,
	}
	if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
		p.listenIP = tcpAddr.IP
		p.listenPort = tcpAddr.Port
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if args.UpstreamTLSInsecure {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	reverse := httputil.NewSingleHostReverseProxy(args.Upstream)
	reverse.Transport = transport
	reverse.ModifyResponse = p.modifyResponse
	reverse.ErrorHandler = p.errorHandler
	p.reverse = reverse

	p.server = &http.Server{Handler: http.HandlerFunc(p.handle)}
	return p, nil
}

// The address the proxy is listening on. Useful when ListenAddr requested an
// ephemeral port.
func (p *Proxy) Addr() net.Addr {
	return p.listener.Addr()
}

// Accepts and forwards traffic until stop is closed. Blocks; always returns a
// non-nil error except after a clean shutdown triggered by stop.
func (p *Proxy) Serve(stop <-chan struct{}) error {
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.server.Shutdown(ctx); err != nil {
			p.server.Close()
		}
	}()

	var err error
	if p.args.TLSCertFile != "" {
		err = p.server.ServeTLS(p.listener, p.args.TLSCertFile, p.args.TLSKeyFile)
	} else {
		err = p.server.Serve(p.listener)
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

type ctxKey struct{}

// Tracks a single request/response exchange through the proxy. The witness
// pair is emitted once, when the response body finishes streaming to the
// client or the exchange fails.
type exchange struct {
	proxy    *Proxy
	streamID uuid.UUID
	request  *http.Request

	start   time.Time
	reqDone time.Time

	reqCapture  *captureReader
	respCapture *captureReader

	respMeta       *http.Response
	respHeaderTime time.Time

	emitOnce sync.Once
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	// Protocol upgrades (e.g. websockets) are not request/response exchanges;
	// pass them through without capture.
	if r.Header.Get("Upgrade") != "" {
		p.reverse.ServeHTTP(w, r)
		return
	}

	ex := &exchange{
		proxy:    p,
		streamID: uuid.New(),
		request:  r,
		start:    time.Now(),
	}
	ex.reqCapture = newCaptureReader(r.Body, p.pool.NewBuffer(), p.maxBody, func() {
		ex.reqDone = time.Now()
	})
	r.Body = ex.reqCapture

	p.reverse.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, ex)))
}

func (p *Proxy) modifyResponse(resp *http.Response) error {
	ex, _ := resp.Request.Context().Value(ctxKey{}).(*exchange)
	if ex == nil {
		return nil
	}
	ex.respHeaderTime = time.Now()

	// Snapshot the response metadata; the server machinery may mutate the
	// original while writing it to the client.
	meta := *resp
	meta.Header = resp.Header.Clone()
	meta.Body = nil
	ex.respMeta = &meta

	ex.respCapture = newCaptureReader(resp.Body, p.pool.NewBuffer(), p.maxBody, ex.emit)
	resp.Body = ex.respCapture
	return nil
}

func (p *Proxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	printer.Warningf("Reverse proxy failed to forward %s %s: %v\n", r.Method, r.URL.Path, err)
	w.WriteHeader(http.StatusBadGateway)

	ex, _ := r.Context().Value(ctxKey{}).(*exchange)
	if ex == nil {
		return
	}
	// Record the 502 actually sent to the client so the endpoint is still
	// discovered.
	ex.respMeta = &http.Response{
		StatusCode: http.StatusBadGateway,
		ProtoMajor: r.ProtoMajor,
		ProtoMinor: r.ProtoMinor,
		Header:     http.Header{},
	}
	ex.respHeaderTime = time.Now()
	ex.emit()
}

func (ex *exchange) emit() {
	ex.emitOnce.Do(func() {
		p := ex.proxy

		reqBody := ex.reqCapture.takeBuffer(p.pool)
		var respBody buffer_pool.Buffer
		if ex.respCapture != nil {
			respBody = ex.respCapture.takeBuffer(p.pool)
		} else {
			respBody = p.pool.NewBuffer()
		}

		reqDone := ex.reqDone
		if reqDone.IsZero() {
			reqDone = ex.start
		}
		respStart := ex.respHeaderTime
		if respStart.IsZero() {
			respStart = time.Now()
		}

		srcIP, srcPort := parseHostPort(ex.request.RemoteAddr)

		reqTraffic := akinet.ParsedNetworkTraffic{
			SrcIP:           srcIP,
			SrcPort:         srcPort,
			DstIP:           p.listenIP,
			DstPort:         p.listenPort,
			Content:         akinet.FromStdRequest(ex.streamID, 0, ex.request, reqBody),
			Interface:       InterfaceName,
			ObservationTime: ex.start,
			FinalPacketTime: reqDone,
		}
		respTraffic := akinet.ParsedNetworkTraffic{
			SrcIP:           p.listenIP,
			SrcPort:         p.listenPort,
			DstIP:           srcIP,
			DstPort:         srcPort,
			Content:         akinet.FromStdResponse(ex.streamID, 0, ex.respMeta, respBody),
			Interface:       InterfaceName,
			ObservationTime: respStart,
			FinalPacketTime: time.Now(),
		}

		p.collectorMu.Lock()
		defer p.collectorMu.Unlock()
		if err := p.collector.Process(reqTraffic); err != nil {
			printer.Errorf("Reverse proxy failed to collect request: %v\n", err)
		}
		if err := p.collector.Process(respTraffic); err != nil {
			printer.Errorf("Reverse proxy failed to collect response: %v\n", err)
		}
	})
}

func parseHostPort(addr string) (net.IP, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0
	}
	port, _ := strconv.Atoi(portStr)
	return net.ParseIP(host), port
}

// Tees a body into a capture buffer as its consumer reads it, and fires
// onDone exactly once when the body is exhausted or closed. Bodies exceeding
// max bytes are passed through but not captured.
type captureReader struct {
	mu       sync.Mutex
	rc       io.ReadCloser
	buf      buffer_pool.Buffer
	max      int
	n        int
	overflow bool
	onDone   func()
	doneOnce sync.Once
}

func newCaptureReader(rc io.ReadCloser, buf buffer_pool.Buffer, max int, onDone func()) *captureReader {
	if rc == nil {
		rc = http.NoBody
	}
	return &captureReader{rc: rc, buf: buf, max: max, onDone: onDone}
}

func (c *captureReader) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		c.mu.Lock()
		if !c.overflow {
			if c.n+n > c.max {
				c.overflow = true
			} else if _, err := c.buf.Write(p[:n]); err != nil {
				c.overflow = true
			} else {
				c.n += n
			}
		}
		c.mu.Unlock()
	}
	if err == io.EOF {
		c.done()
	}
	return n, err
}

func (c *captureReader) Close() error {
	err := c.rc.Close()
	c.done()
	return err
}

func (c *captureReader) done() {
	c.doneOnce.Do(func() {
		if c.onDone != nil {
			c.onDone()
		}
	})
}

// Returns the captured body, or a fresh empty buffer if capture overflowed.
func (c *captureReader) takeBuffer(pool buffer_pool.BufferPool) buffer_pool.Buffer {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.overflow {
		c.buf.Release()
		return pool.NewBuffer()
	}
	return c.buf
}
