// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package uprobes

import (
	"fmt"
	"io"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
)

// GoManager attaches go_tls uprobes to Go binaries and tracks them per PID.
// Unlike the libssl Manager (symbol uprobes on a shared object), Go capture
// resolves crypto/tls.(*Conn).Write/Read and each of their RET offsets from
// the target ELF (goTLSSymbols) and attaches an entry uprobe plus one uprobe
// per RET site — NOT a uretprobe, because Go moves goroutine stacks.
type GoManager struct {
	loader *loader.GoTLSLoader

	mu       sync.Mutex
	attached map[uint32]*goAttachment
}

type goAttachment struct {
	path  string
	links []io.Closer
}

// NewGoManager wires a GoManager to a loader whose go_tls programs are loaded.
func NewGoManager(l *loader.GoTLSLoader) *GoManager {
	return &GoManager{loader: l, attached: make(map[uint32]*goAttachment)}
}

// AttachGoTLS resolves the crypto/tls entry points in the binary at path and
// attaches the go_tls programs (entry uprobe + one uprobe per RET offset for
// both Write and Read). It returns an error if path is not a Go binary or
// does not link crypto/tls; callers treat that as "not a Go TLS target".
// Repeated calls for the same live PID+path are no-ops.
func (m *GoManager) AttachGoTLS(pid uint32, path string) error {
	m.mu.Lock()
	if att, ok := m.attached[pid]; ok {
		if procAlive(pid) && att.path == path {
			m.mu.Unlock()
			return nil
		}
		m.mu.Unlock()
		_ = m.Detach(pid)
	} else {
		m.mu.Unlock()
	}

	write, read, err := goTLSSymbols(path)
	if err != nil {
		return err
	}

	exe, err := link.OpenExecutable(path)
	if err != nil {
		return fmt.Errorf("gotls: open %s: %w", path, err)
	}

	att := &goAttachment{path: path}
	cleanup := func() {
		for _, c := range att.links {
			_ = c.Close()
		}
	}

	type hook struct {
		fn    *goFunc
		entry *ebpf.Program
		ret   *ebpf.Program
	}
	hooks := []hook{
		{write, m.loader.WriteEntryProg(), m.loader.WriteRetProg()},
		{read, m.loader.ReadEntryProg(), m.loader.ReadRetProg()},
	}

	for _, h := range hooks {
		// Entry uprobe at the function's file offset (goelf already converted
		// the gosym vaddr; UprobeOptions.Address is a raw file offset).
		up, err := exe.Uprobe("", h.entry, &link.UprobeOptions{PID: int(pid), Address: h.fn.Entry})
		if err != nil {
			cleanup()
			return fmt.Errorf("gotls: attach entry %s pid=%d: %w", h.fn.Name, pid, err)
		}
		att.links = append(att.links, up)

		// One uprobe per RET site — safe stand-in for a uretprobe on Go.
		for _, off := range h.fn.RetOffsets {
			ret, err := exe.Uprobe("", h.ret, &link.UprobeOptions{PID: int(pid), Address: h.fn.Entry + off})
			if err != nil {
				cleanup()
				return fmt.Errorf("gotls: attach ret %s+%#x pid=%d: %w", h.fn.Name, off, pid, err)
			}
			att.links = append(att.links, ret)
		}
	}

	if err := m.loader.AddTargetPID(pid); err != nil {
		cleanup()
		return fmt.Errorf("gotls: add target pid=%d: %w", pid, err)
	}

	m.mu.Lock()
	m.attached[pid] = att
	m.mu.Unlock()
	return nil
}

// Detach closes all go_tls uprobes attached to pid and drops it from the
// allowlist. Safe to call multiple times.
func (m *GoManager) Detach(pid uint32) error {
	m.mu.Lock()
	att, ok := m.attached[pid]
	delete(m.attached, pid)
	m.mu.Unlock()
	if !ok {
		return nil
	}
	_ = m.loader.DeleteTargetPID(pid)
	return closeLinks(att.links)
}

// Close detaches every probe owned by this manager.
func (m *GoManager) Close() error {
	m.mu.Lock()
	pids := make([]uint32, 0, len(m.attached))
	for pid := range m.attached {
		pids = append(pids, pid)
	}
	m.mu.Unlock()

	var firstErr error
	for _, pid := range pids {
		if err := m.Detach(pid); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// AttachedPIDs returns the PIDs currently traced. Used for telemetry.
func (m *GoManager) AttachedPIDs() []uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]uint32, 0, len(m.attached))
	for pid := range m.attached {
		out = append(out, pid)
	}
	return out
}

// ProbeCount returns the number of uprobe links attached to pid.
func (m *GoManager) ProbeCount(pid uint32) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if att, ok := m.attached[pid]; ok {
		return len(att.links)
	}
	return 0
}
