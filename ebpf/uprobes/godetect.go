// SPDX-License-Identifier: Apache-2.0

package uprobes

import (
	"debug/elf"
	"debug/gosym"
	"fmt"
)

// GoExePath identifies a process whose main executable is a Go binary that
// links crypto/tls -- the discovery-side signal that a PID is a Go TLS
// capture target. It is the Go analogue of LibSSLPath, which plays the same
// role for OpenSSL.
type GoExePath struct {
	// PID this executable was discovered for.
	PID uint32

	// HostPath is the agent-visible path to the Go executable (typically
	// /proc/<pid>/root/<exe> inside containers) that link.OpenExecutable and
	// the go_tls attach path open. The opened inode must match the target's
	// mapped text so uprobe file offsets line up.
	HostPath string
}

// ErrNotGoTLS is returned by FindGoExeAt when a PID's executable is not a Go
// binary, or is a Go binary that does not link crypto/tls. Callers treat it
// the way FindLibSSL callers treat ErrNotFound: "not a target for this
// backend," not a hard error.
var ErrNotGoTLS = fmt.Errorf("uprobes: not a Go crypto/tls binary")

// FindGoExeAt reports whether the process pid (under procRoot) runs a Go
// binary that links crypto/tls, and if so returns the agent-visible path to
// attach go_tls uprobes to. This is the light discovery gate: it parses the
// pcln symbol table only (no disassembly). The heavier RET-site resolution
// runs later, once, at attach time (see GoManager.AttachGoTLS).
func FindGoExeAt(procRoot string, pid uint32) (*GoExePath, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	path := staticExecutableAttachPath(procRoot, pid)
	if !isGoTLSBinary(path) {
		return nil, ErrNotGoTLS
	}
	return &GoExePath{PID: pid, HostPath: path}, nil
}

// isGoTLSBinary reports whether the ELF at path is a Go binary (has a
// .gopclntab) that links both crypto/tls entry points we hook. It reads the
// pcln table rather than DWARF so it also matches stripped
// (-ldflags="-s -w") binaries. Any failure to open or parse yields false --
// the PID is simply not treated as a Go TLS target. The symbol strings are
// kept in sync with goTLSWriteSym / goTLSReadSym in goelf_linux.go.
func isGoTLSBinary(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	textSec := f.Section(".text")
	pclnSec := f.Section(".gopclntab")
	if textSec == nil || pclnSec == nil {
		return false
	}
	pclnData, err := pclnSec.Data()
	if err != nil {
		return false
	}
	tab, err := gosym.NewTable(nil, gosym.NewLineTable(pclnData, textSec.Addr))
	if err != nil {
		return false
	}
	return tab.LookupFunc("crypto/tls.(*Conn).Write") != nil &&
		tab.LookupFunc("crypto/tls.(*Conn).Read") != nil
}
