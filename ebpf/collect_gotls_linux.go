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
	goidOff  uint64

	mu     sync.Mutex
	closed bool
}

// NewGoTLSCollector loads the go_tls programs and constructs a collector that
// feeds captured plaintext into the supplied adapter. The BPF program carries
// a single runtime.g.goid offset (used to correlate the entry and RET
// uprobes); the collector self-configures it from the first Go binary it can
// see under procRoot, falling back to the value that is stable across Go
// 1.18-1.25 when no Go workload is running yet. Heterogeneous Go *major*
// versions inside one scope would need per-PID offsets -- see the design
// doc's limitations section.
func NewGoTLSCollector(maxCaptureBytes uint32, adapter *events.Adapter, procRoot string) (*GoTLSCollector, error) {
	if adapter == nil {
		return nil, fmt.Errorf("ebpf: GoTLSCollector requires an Adapter")
	}
	goidOff := resolveGoidOffset(procRoot)
	l, err := loader.LoadGoTLS(maxCaptureBytes, false, goidOff)
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
		goidOff:  goidOff,
	}, nil
}

// resolveGoidOffset scans procRoot for the first Go+crypto/tls process and
// returns its runtime.g.goid offset. Returns the Go 1.18-1.25 default (152)
// when no such process is visible yet or the offset can't be read.
func resolveGoidOffset(procRoot string) uint64 {
	if ts, err := discovery.ScanProcGoAt(procRoot); err == nil {
		for _, t := range ts {
			if t.Go == nil {
				continue
			}
			if off := uprobes.GoidOffset(t.Go.HostPath); off != 0 {
				return off
			}
		}
	}
	return 152
}

// GoidOffset returns the runtime.g.goid offset the BPF program was loaded
// with (diagnostics / tests).
func (c *GoTLSCollector) GoidOffset() uint64 { return c.goidOff }

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
