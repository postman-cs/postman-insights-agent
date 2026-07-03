// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/postmanlabs/postman-insights-agent/ebpf/discovery"
	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
	"github.com/postmanlabs/postman-insights-agent/ebpf/uprobes"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// GoTLSCollector is the discovery-native Go crypto/tls capture path. Unlike
// JavaTLSCollector (one global kprobe, no per-binary inspection) it owns a
// per-PID attach loop: it runs its own process discovery, and for every
// discovered Go binary that links crypto/tls it resolves the entry/RET sites
// and attaches go_tls uprobes -- with no per-service configuration and no
// agent injection. This is what makes Go capture "discovery-mode": drop the
// agent in, and any Go HTTPS workload that appears is picked up
// automatically, exactly like the libssl path.
type GoTLSCollector struct {
	loader   *loader.GoTLSLoader
	mgr      *uprobes.GoManager
	reader   *events.Reader
	adapter  *events.Adapter
	procRoot string
	interval time.Duration

	mu     sync.Mutex
	closed bool
}

// NewGoTLSCollector loads the go_tls programs and constructs a collector that
// feeds captured plaintext into the supplied adapter. The runtime.g.goid
// offset is resolved and published per-PID as each Go binary is attached (see
// GoManager.AttachGoTLS), so a scope mixing Go *major* versions whose goid
// offsets differ correlates every PID on its own offset -- no single load-time
// constant, no minority-version mis-keying.
func NewGoTLSCollector(maxCaptureBytes uint32, adapter *events.Adapter, procRoot string) (*GoTLSCollector, error) {
	if adapter == nil {
		return nil, fmt.Errorf("ebpf: GoTLSCollector requires an Adapter")
	}
	l, err := loader.LoadGoTLS(maxCaptureBytes, false)
	if err != nil {
		return nil, err
	}
	r, err := events.NewReader(l.EventsMap(), 4096)
	if err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("ebpf: go_tls ringbuf reader: %w", err)
	}
	return &GoTLSCollector{
		loader:   l,
		mgr:      uprobes.NewGoManager(l),
		reader:   r,
		adapter:  adapter,
		procRoot: procRoot,
		interval: 5 * time.Second,
	}, nil
}

// AttachedPIDs returns the PIDs currently attached (diagnostics / tests).
func (c *GoTLSCollector) AttachedPIDs() []uint32 { return c.mgr.AttachedPIDs() }

// CounterEmitted returns the number of plaintext events the BPF program has
// pushed onto the ringbuf.
func (c *GoTLSCollector) CounterEmitted() uint64 {
	v, _ := c.loader.ReadCounter(loader.GoCounterEventsEmitted)
	return v
}

// CounterMissingStash returns the number of RET probes that fired without a
// matching entry stash (should stay 0 once goid correlation is working).
func (c *GoTLSCollector) CounterMissingStash() uint64 {
	v, _ := c.loader.ReadCounter(loader.GoCounterMissingStash)
	return v
}

// Run drives discovery + attach and pumps captured events into the adapter
// until ctx is cancelled. It builds its own discovery channel; use
// RunWithDiscovery to supply a pre-scoped one (namespace / netns filtered).
func (c *GoTLSCollector) Run(ctx context.Context, monoEpoch time.Time) {
	disco := discovery.WatchWith(ctx, discovery.WatchOpts{
		Interval: c.interval,
		ProcRoot: c.procRoot,
		DetectGo: true,
	})
	c.RunWithDiscovery(ctx, monoEpoch, disco)
}

// RunWithDiscovery is Run with a caller-supplied discovery channel, so the
// DaemonSet per-pod path can pass a netns-scoped source (mirrors Collect's
// Args.Discovery). The channel may carry libssl targets too; those are
// ignored here.
func (c *GoTLSCollector) RunWithDiscovery(ctx context.Context, monoEpoch time.Time, disco <-chan discovery.Target) {
	readerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		if err := c.reader.Run(readerCtx); err != nil {
			printer.Errorf("ebpf: go_tls reader stopped: %v\n", err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return

		case tgt, ok := <-disco:
			if !ok {
				disco = nil
				continue
			}
			if tgt.Removed {
				if err := c.mgr.Detach(tgt.PID); err == nil {
					printer.Debugf("ebpf: detached go_tls uprobes pid=%d\n", tgt.PID)
				}
				continue
			}
			if tgt.Go == nil {
				continue // libssl target on a shared channel -- not ours
			}
			if err := c.mgr.AttachGoTLS(tgt.PID, tgt.Go.HostPath); err != nil {
				printer.Debugf("ebpf: attach go_tls pid=%d path=%s failed: %v\n",
					tgt.PID, tgt.Go.HostPath, err)
				continue
			}
			printer.Stderr.Infof("ebpf: attached go_tls uprobes pid=%d path=%s probes=%d\n",
				tgt.PID, tgt.Go.HostPath, c.mgr.ProbeCount(tgt.PID))

		case ev, ok := <-c.reader.Out:
			if !ok {
				return
			}
			c.adapter.Feed(ev, monoEpoch)
		}
	}
}

// Close detaches all uprobes, closes the reader, and frees BPF resources.
func (c *GoTLSCollector) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	_ = c.mgr.Close()
	_ = c.reader.Close()
	return c.loader.Close()
}
