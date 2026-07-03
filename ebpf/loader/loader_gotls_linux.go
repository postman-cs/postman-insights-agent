// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package loader

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations" gotls ../programs/go_tls.bpf.c -- -I../programs

// goTLSMaxCapture is MAX_EVENT_PAYLOAD-1 (see programs/event.h and
// go_tls.bpf.c). The BPF side bounds the plaintext read length with a
// "& (MAX_EVENT_PAYLOAD-1)" mask — the only construct the verifier accepts
// there — so keeping the runtime cap at or below this value ensures the mask
// never truncates a capture.
const goTLSMaxCapture = 1023

// GoTLSLoader owns the kernel-side go_tls program set. Go statically links
// crypto/tls, so — unlike libssl (shared object, symbol uprobes) and java_tls
// (a single sys_ioctl kprobe) — attachment is per-Go-binary: the uprobes
// package resolves crypto/tls.(*Conn).Write/Read plus each of their RET
// offsets from the target ELF and attaches this loader's programs there.
type GoTLSLoader struct {
	gotls *gotlsObjects
}

// LoadGoTLS instantiates the go_tls BPF collection. enforceAllowlist gates
// whether non-allowlisted PIDs emit. The runtime.g.goid offset is no longer a
// load-time constant: it is published per-PID via SetGoidOffset when each Go
// binary is attached, so a scope mixing Go major versions correlates every PID
// on its own offset.
func LoadGoTLS(maxCaptureBytes uint32, enforceAllowlist bool) (*GoTLSLoader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpf: remove memlock: %w", err)
	}
	spec, err := loadGotls()
	if err != nil {
		return nil, fmt.Errorf("ebpf: load go_tls spec: %w", err)
	}
	if maxCaptureBytes == 0 || maxCaptureBytes > goTLSMaxCapture {
		maxCaptureBytes = goTLSMaxCapture
	}
	var enforce uint32
	if enforceAllowlist {
		enforce = 1
	}
	if err := spec.Variables["go_enforce_pid_allowlist"].Set(enforce); err != nil {
		return nil, fmt.Errorf("ebpf: set go_enforce_pid_allowlist: %w", err)
	}
	if err := spec.Variables["go_max_capture_bytes"].Set(maxCaptureBytes); err != nil {
		return nil, fmt.Errorf("ebpf: set go_max_capture_bytes: %w", err)
	}
	objs := &gotlsObjects{}
	if err := spec.LoadAndAssign(objs, &ebpf.CollectionOptions{}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("ebpf: go_tls verifier rejected:\n%+v", ve)
		}
		return nil, fmt.Errorf("ebpf: go_tls load: %w", err)
	}
	return &GoTLSLoader{gotls: objs}, nil
}

// Close releases all maps and programs. Callers MUST close any link.Link
// handles for attached probes BEFORE calling Close.
func (l *GoTLSLoader) Close() error {
	if l.gotls != nil {
		return l.gotls.Close()
	}
	return nil
}

// EventsMap returns the ringbuf carrying struct ssl_event records. The ABI is
// shared with libssl/java_tls, so events.Adapter consumes it identically.
func (l *GoTLSLoader) EventsMap() *ebpf.Map { return l.gotls.GoEvents }

// AddTargetPID adds a PID to the capture allowlist.
func (l *GoTLSLoader) AddTargetPID(pid uint32) error {
	one := uint8(1)
	return l.gotls.GoTargetPids.Update(&pid, &one, ebpf.UpdateAny)
}

// DeleteTargetPID removes a PID from the capture allowlist.
func (l *GoTLSLoader) DeleteTargetPID(pid uint32) error {
	return l.gotls.GoTargetPids.Delete(&pid)
}

// SetGoidOffset publishes the runtime.g.goid byte offset for pid's Go binary.
// The attach path calls this BEFORE attaching pid's uprobes so the entry/RET
// correlation keys on the correct goid for that binary's Go version. An offset
// of 0 means "unknown"; the BPF program then falls back to the OS tid.
func (l *GoTLSLoader) SetGoidOffset(pid uint32, offset uint64) error {
	return l.gotls.GoGoidOffsets.Update(&pid, &offset, ebpf.UpdateAny)
}

// DeleteGoidOffset removes pid's published goid offset (on detach).
func (l *GoTLSLoader) DeleteGoidOffset(pid uint32) error {
	return l.gotls.GoGoidOffsets.Delete(&pid)
}

// Program accessors used by the uprobes package to attach at resolved offsets.
func (l *GoTLSLoader) WriteEntryProg() *ebpf.Program { return l.gotls.GoTlsWriteEntry }
func (l *GoTLSLoader) WriteRetProg() *ebpf.Program   { return l.gotls.GoTlsWriteRet }
func (l *GoTLSLoader) ReadEntryProg() *ebpf.Program  { return l.gotls.GoTlsReadEntry }
func (l *GoTLSLoader) ReadRetProg() *ebpf.Program    { return l.gotls.GoTlsReadRet }

// Go-side counter indices — must match go_tls.bpf.c.
const (
	GoCounterEventsEmitted uint32 = 0
	GoCounterEventsDropped uint32 = 1
	GoCounterReadFailed    uint32 = 2
	GoCounterGoidFailed    uint32 = 3
	GoCounterMissingStash  uint32 = 4
)

// ReadCounter sums the per-CPU values for a go_tls counter index.
func (l *GoTLSLoader) ReadCounter(idx uint32) (uint64, error) {
	var perCPU []uint64
	if err := l.gotls.GoCounters.Lookup(&idx, &perCPU); err != nil {
		return 0, fmt.Errorf("ebpf: read go counter %d: %w", idx, err)
	}
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum, nil
}

// GoTLSMaxCaptureForTest exposes the internal capture cap to the uprobes
// package's e2e test without widening the production surface.
func GoTLSMaxCaptureForTest() uint32 { return goTLSMaxCapture }
