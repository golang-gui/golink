// Package golink links a bounded set of native ARM64 objects emitted by Go.
// It does not compile Go, replace the Go runtime, or discover host SDKs.
package golink

import (
	"bytes"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const Version = "0.2.0"

// Request is the versioned, host-independent native link protocol. Input paths
// are explicit; Libraries are target ELF shared objects, never host libraries.
// Format 1 supports Android ELF and iOS Mach-O ARM64. IOS selects device or
// simulator metadata. Reexports supplies explicit supplemental TBD inputs.
// Debug sections are omitted. Unsupported native features fail explicitly.
type Request struct {
	Format    int         `json:"format"`
	Target    string      `json:"target"`
	Output    string      `json:"output"`
	Objects   []string    `json:"objects"`
	Archives  []string    `json:"archives,omitempty"`
	Libraries []string    `json:"libraries,omitempty"`
	Reexports []string    `json:"reexports,omitempty"`
	SONAME    string      `json:"soname,omitempty"`
	Entry     string      `json:"entry,omitempty"`
	Symbolic  bool        `json:"symbolic,omitempty"`
	NoDelete  bool        `json:"nodelete,omitempty"`
	IOS       *IOSOptions `json:"ios,omitempty"`
}

// IOSOptions selects the SDK platform metadata. Libraries are explicit TBD v4
// files. Archives are consumed in full, matching Go's external-archive output.
type IOSOptions struct {
	Variant        string `json:"variant"`
	MinimumVersion string `json:"minimum_version"`
	SDKVersion     string `json:"sdk_version"`
}

type linkError struct{ error }

// ReadRequest rejects unknown fields, trailing data and oversized requests.
func ReadRequest(r io.Reader) (Request, error) {
	var request Request
	data, err := io.ReadAll(io.LimitReader(r, (8<<20)+1))
	if err != nil {
		return request, err
	}
	if len(data) > 8<<20 {
		return request, fmt.Errorf("link request exceeds 8 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(&request); err != nil {
		return request, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return request, fmt.Errorf("trailing link request data")
	}
	return request, request.validate()
}

func (r Request) validate() error {
	if r.Format != 1 || (r.Target != "android/arm64" && r.Target != "ios/arm64") {
		return fmt.Errorf("unsupported link format/target: %d %q", r.Format, r.Target)
	}
	if r.Target == "ios/arm64" {
		if r.IOS == nil || (r.IOS.Variant != "device" && r.IOS.Variant != "simulator") || r.Symbolic || r.NoDelete || r.SONAME != "" {
			return fmt.Errorf("invalid iOS link options")
		}
		minimum, err := machoVersion(r.IOS.MinimumVersion)
		if err != nil {
			return err
		}
		sdk, err := machoVersion(r.IOS.SDKVersion)
		if err != nil {
			return err
		}
		if minimum > sdk {
			return fmt.Errorf("iOS minimum version exceeds SDK version")
		}
	} else if r.IOS != nil || len(r.Reexports) != 0 {
		return fmt.Errorf("iOS options on Android request")
	}
	if r.Output == "" || len(r.Objects)+len(r.Archives) == 0 || len(r.Objects)+len(r.Archives)+len(r.Libraries)+len(r.Reexports) > 65536 {
		return fmt.Errorf("link requires output and bounded object inputs")
	}
	for _, list := range [][]string{r.Objects, r.Archives, r.Libraries, r.Reexports, {r.Output}} {
		for _, name := range list {
			if name == "" || strings.ContainsAny(name, "\x00\r\n") {
				return fmt.Errorf("invalid link path %q", name)
			}
		}
	}
	if strings.ContainsAny(r.SONAME, "/\\\x00\r\n") || strings.ContainsAny(r.Entry, "\x00\r\n") {
		return fmt.Errorf("invalid SONAME or entry")
	}
	return nil
}

// Link writes a complete output only after all inputs and relocations succeed.
// It never invokes another process. Runtime panics are not converted to success
// or disguised as unsupported input; expected input errors are returned.
func Link(r Request) (err error) {
	if err = r.validate(); err != nil {
		return err
	}
	defer func() {
		if v := recover(); v != nil {
			if failure, ok := v.(linkError); ok {
				err = failure.error
			} else {
				panic(v)
			}
		}
	}()
	var data []byte
	if r.Target == "ios/arm64" {
		data = linkMachO(r)
	} else {
		data = linkELF(r)
	}
	temp, err := os.CreateTemp(filepath.Dir(r.Output), ".golink-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err = temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Chmod(0755); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), r.Output)
}

func linkELF(r Request) []byte {
	l := &linker{globals: map[string]*symbol{}, libSymbols: map[string]bool{}, entryName: r.Entry, soname: r.SONAME, symbolic: r.Symbolic, nodelete: r.NoDelete}
	seen := map[string]bool{}
	for _, path := range r.Libraries {
		l.loadLibrary(path, seen)
	}
	for _, path := range r.Objects {
		data, err := os.ReadFile(path)
		check(err == nil, "read object %s: %v", path, err)
		l.load(path, data)
	}
	l.loadArchives(r.Archives)
	l.prepare()
	l.finishTables()
	return l.emit()
}

func (l *linker) loadLibrary(path string, seen map[string]bool) {
	f, err := elf.Open(path)
	check(err == nil, "read target library %s: %v", path, err)
	defer f.Close()
	check(f.Class == elf.ELFCLASS64 && f.Data == elf.ELFDATA2LSB && f.Machine == elf.EM_AARCH64 && f.Type == elf.ET_DYN, "unsupported target library %s", path)
	syms, err := f.DynamicSymbols()
	check(err == nil, "target library symbols %s: %v", path, err)
	soname, err := f.DynString(elf.DT_SONAME)
	check(err == nil && len(soname) == 1 && soname[0] != "" && !strings.ContainsAny(soname[0], "/\\\x00"), "target library needs one SONAME: %s", path)
	if seen[soname[0]] {
		return
	}
	seen[soname[0]] = true
	l.libs = append(l.libs, soname[0])
	for _, s := range syms {
		bind, visibility := elf.ST_BIND(s.Info), s.Other&3
		if s.Section != elf.SHN_UNDEF && (bind == elf.STB_GLOBAL || bind == elf.STB_WEAK) && (visibility == 0 || visibility == 3) {
			l.libSymbols[s.Name] = true
		}
	}
}

func (l *linker) dynamicFlags() uint64 {
	v := uint64(elf.DF_BIND_NOW)
	if l.symbolic {
		v |= uint64(elf.DF_SYMBOLIC)
	}
	return v
}

func (l *linker) dynamicFlags1() uint64 {
	v := uint64(elf.DF_1_NOW)
	if l.nodelete {
		v |= uint64(elf.DF_1_NODELETE)
	}
	return v
}
