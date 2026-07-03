// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package uprobes

import (
	"debug/buildinfo"
	"debug/dwarf"
	"debug/elf"
	"debug/gosym"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

// The crypto/tls entry points we hook. A method receiver is the first Go-ABI
// argument, so at entry reg0 = *Conn, reg1 = b.ptr, reg2 = b.len; at the RET
// site reg0 = n (see go_tls.bpf.c).
const (
	goTLSWriteSym = "crypto/tls.(*Conn).Write"
	goTLSReadSym  = "crypto/tls.(*Conn).Read"
)

// goFunc describes one resolved function: its entry file offset (ready to
// pass as UprobeOptions.Address) and the offsets (from Entry) of every RET
// instruction in its body.
type goFunc struct {
	Name       string
	Entry      uint64
	RetOffsets []uint64
}

// goTLSSymbols resolves the Write and Read functions from the Go binary at
// path. It reads .gopclntab (present even in stripped binaries) so it works
// regardless of -ldflags="-s -w". Returns an error if path is not a Go binary
// or does not link crypto/tls — the caller treats that as "not a Go TLS
// target" rather than a hard failure.
func goTLSSymbols(path string) (write, read *goFunc, err error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("goelf: open %s: %w", path, err)
	}
	defer f.Close()

	textSec := f.Section(".text")
	if textSec == nil {
		return nil, nil, fmt.Errorf("goelf: %s has no .text", path)
	}
	pclnSec := f.Section(".gopclntab")
	if pclnSec == nil {
		return nil, nil, fmt.Errorf("goelf: %s has no .gopclntab (not a Go binary?)", path)
	}
	pclnData, err := pclnSec.Data()
	if err != nil {
		return nil, nil, fmt.Errorf("goelf: read .gopclntab: %w", err)
	}
	textData, err := textSec.Data()
	if err != nil {
		return nil, nil, fmt.Errorf("goelf: read .text: %w", err)
	}
	tab, err := gosym.NewTable(nil, gosym.NewLineTable(pclnData, textSec.Addr))
	if err != nil {
		return nil, nil, fmt.Errorf("goelf: parse pclntab: %w", err)
	}

	resolve := func(sym string) (*goFunc, error) {
		fn := tab.LookupFunc(sym)
		if fn == nil {
			return nil, fmt.Errorf("goelf: symbol %q not found in %s", sym, path)
		}
		end := textSec.Addr + uint64(len(textData))
		if fn.Entry < textSec.Addr || fn.End > end || fn.End <= fn.Entry {
			return nil, fmt.Errorf("goelf: %q range [%#x,%#x) outside .text", sym, fn.Entry, fn.End)
		}
		code := textData[fn.Entry-textSec.Addr : fn.End-textSec.Addr]
		rets, err := findRetOffsets(f.Machine, code)
		if err != nil {
			return nil, fmt.Errorf("goelf: scan %q: %w", sym, err)
		}
		if len(rets) == 0 {
			return nil, fmt.Errorf("goelf: %q has no RET instructions", sym)
		}
		entryOff, err := vaddrToOffset(f, fn.Entry)
		if err != nil {
			return nil, fmt.Errorf("goelf: offset for %q: %w", sym, err)
		}
		return &goFunc{Name: sym, Entry: entryOff, RetOffsets: rets}, nil
	}

	if write, err = resolve(goTLSWriteSym); err != nil {
		return nil, nil, err
	}
	if read, err = resolve(goTLSReadSym); err != nil {
		return nil, nil, err
	}
	return write, read, nil
}

// findRetOffsets disassembles code and returns the offset of every function
// return. Go moves goroutine stacks, making uretprobes unsafe; we attach an
// ordinary uprobe at each RET instead (see go_tls.bpf.c header comment).
func findRetOffsets(machine elf.Machine, code []byte) ([]uint64, error) {
	switch machine {
	case elf.EM_X86_64:
		return findRetOffsetsAMD64(code), nil
	case elf.EM_AARCH64:
		return findRetOffsetsARM64(code), nil
	default:
		return nil, fmt.Errorf("goelf: unsupported machine %v", machine)
	}
}

// amd64 has variable-length (1-15 byte) instructions, so we must decode
// linearly and resync a byte at a time on the rare undecodable padding.
func findRetOffsetsAMD64(code []byte) []uint64 {
	var rets []uint64
	for i := 0; i < len(code); {
		inst, err := x86asm.Decode(code[i:], 64)
		if err != nil || inst.Len == 0 {
			i++
			continue
		}
		if inst.Op == x86asm.RET {
			rets = append(rets, uint64(i))
		}
		i += inst.Len
	}
	return rets
}

// arm64 instructions are a fixed 4 bytes.
func findRetOffsetsARM64(code []byte) []uint64 {
	var rets []uint64
	for i := 0; i+4 <= len(code); i += 4 {
		inst, err := arm64asm.Decode(code[i : i+4])
		if err != nil {
			continue
		}
		if inst.Op == arm64asm.RET {
			rets = append(rets, uint64(i))
		}
	}
	return rets
}

// vaddrToOffset converts a virtual address to a file offset using the
// executable PT_LOAD segment that contains it. Uprobe attachment is
// file-offset based (inode + offset), so gosym vaddrs must be converted
// before they are handed to cilium/ebpf as UprobeOptions.Address (which,
// unlike the symbol-based path, does NOT do this conversion itself).
func vaddrToOffset(f *elf.File, vaddr uint64) (uint64, error) {
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if vaddr >= p.Vaddr && vaddr < p.Vaddr+p.Memsz {
			return vaddr - p.Vaddr + p.Off, nil
		}
	}
	return 0, fmt.Errorf("goelf: vaddr %#x not in any PT_LOAD segment", vaddr)
}

// goidOffset returns the byte offset of runtime.g.goid for the Go binary at
// path, or 0 if it cannot be determined (the BPF program then falls back to
// the OS tid as the entry/return correlation key). DWARF (present in
// unstripped binaries) is authoritative; a version table covers stripped
// binaries built with a known modern Go toolchain.
func goidOffset(path string) uint64 {
	if off, ok := goidOffsetFromDWARF(path); ok {
		return off
	}
	return goidOffsetFromVersion(path)
}

func goidOffsetFromDWARF(path string) (uint64, bool) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	d, err := f.DWARF()
	if err != nil {
		return 0, false
	}
	r := d.Reader()
	for {
		e, err := r.Next()
		if err != nil || e == nil {
			return 0, false
		}
		if e.Tag != dwarf.TagStructType {
			continue
		}
		if name, _ := e.Val(dwarf.AttrName).(string); name != "runtime.g" {
			continue
		}
		for {
			c, err := r.Next()
			if err != nil || c == nil || c.Tag == 0 {
				return 0, false
			}
			if c.Tag != dwarf.TagMember {
				continue
			}
			if mn, _ := c.Val(dwarf.AttrName).(string); mn == "goid" {
				if off, ok := c.Val(dwarf.AttrDataMemberLoc).(int64); ok && off >= 0 {
					return uint64(off), true
				}
				return 0, false
			}
		}
	}
}

// goidOffsetFromVersion covers stripped binaries. runtime.g.goid has sat at
// offset 152 on 64-bit platforms across Go 1.18 through 1.25 (verified via
// DWARF); we ship that value for that range and fall back to the tid key (0)
// for anything we can't positively identify.
func goidOffsetFromVersion(path string) uint64 {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return 0
	}
	v := strings.TrimPrefix(info.GoVersion, "go1.")
	if v == info.GoVersion {
		return 0 // not a "go1.x" string
	}
	if dot := strings.IndexByte(v, '.'); dot >= 0 {
		v = v[:dot]
	}
	minor, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	if minor >= 18 && minor <= 25 {
		return 152
	}
	return 0
}

// GoidOffset returns the runtime.g.goid offset for the Go binary at path (0
// if it cannot be determined). Exported for the go_tls collector, which loads
// it as a BPF constant. See goidOffset for resolution details.
func GoidOffset(path string) uint64 { return goidOffset(path) }
