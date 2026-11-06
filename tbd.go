package golink

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type tbdGroup struct {
	targets []string
	fields  map[string][]string
}
type tbdDocument struct {
	name               string
	version4           bool
	current, compat    uint32
	targets            []string
	exports, reexports []tbdGroup
	children           []tbdGroup
}
type machoLibrary struct {
	name            string
	symbols         map[string]bool
	reexports       []string
	current, compat uint32
}

// SDK TBD v4 uses mappings, scalar strings and flow sequences. Parse only that
// declared subset, not arbitrary YAML. A target's reexport closure stays within
// the supplied documents or explicit library inputs; no SDK search occurs.
func readTBD(path, target string) machoLibrary {
	b, err := os.ReadFile(path)
	check(err == nil, "read TBD %s: %v", path, err)
	check(len(b) <= 16<<20, "TBD too large")
	var docs []*tbdDocument
	var doc *tbdDocument
	var group *tbdGroup
	mode := ""
	lines := strings.Split(string(b), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || line == "..." || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "---") {
			check(line == "--- !tapi-tbd", "unsupported TBD document %s", line)
			doc = &tbdDocument{current: 1 << 16, compat: 1 << 16}
			docs = append(docs, doc)
			mode = ""
			group = nil
			continue
		}
		check(doc != nil, "missing TBD document header")
		top := len(lines[i]) == len(strings.TrimLeft(lines[i], " "))
		newGroup := strings.HasPrefix(line, "- ")
		if newGroup {
			line = strings.TrimSpace(line[2:])
		}
		colon := strings.IndexByte(line, ':')
		check(colon > 0, "invalid TBD mapping")
		key, value := line[:colon], strings.TrimSpace(line[colon+1:])
		if strings.HasPrefix(value, "[") {
			var list strings.Builder
			quoted := false
			chunk := value
			for {
				list.WriteString(chunk)
				if flowChunkComplete(chunk, &quoted) {
					break
				}
				i++
				check(i < len(lines), "unterminated TBD sequence")
				list.WriteByte(' ')
				chunk = strings.TrimSpace(lines[i])
			}
			value = list.String()
		}
		if top {
			mode = key
			group = nil
			switch key {
			case "tbd-version":
				check(value == "4", "unsupported TBD version %s", value)
				doc.version4 = true
			case "targets":
				doc.targets = tbdList(value)
			case "install-name":
				doc.name = tbdScalar(value)
			case "current-version", "compatibility-version":
				v, e := machoVersion(value)
				check(e == nil, "invalid TBD library version: %v", e)
				if key == "current-version" {
					doc.current = v
				} else {
					doc.compat = v
				}
			case "exports", "reexports", "reexported-libraries":
				check(value == "", "expected TBD group sequence")
			case "flags":
				check(len(tbdList(value)) == 0, "unsupported TBD flags")
			}
			continue
		}
		if mode != "exports" && mode != "reexports" && mode != "reexported-libraries" {
			continue
		}
		if newGroup {
			check(key == "targets", "TBD group must declare targets first")
			g := tbdGroup{targets: tbdList(value), fields: map[string][]string{}}
			switch mode {
			case "exports":
				doc.exports = append(doc.exports, g)
				group = &doc.exports[len(doc.exports)-1]
			case "reexports":
				doc.reexports = append(doc.reexports, g)
				group = &doc.reexports[len(doc.reexports)-1]
			case "reexported-libraries":
				doc.children = append(doc.children, g)
				group = &doc.children[len(doc.children)-1]
			}
		} else {
			check(group != nil, "TBD field outside group")
			check(key == "symbols" || key == "weak-symbols" || key == "weak-def-symbols" || key == "objc-classes" || key == "objc-eh-types" || key == "objc-ivars" || key == "libraries" || key == "thread-local-symbols", "unsupported TBD export field %s", key)
			group.fields[key] = tbdList(value)
		}
	}
	check(len(docs) > 0 && docs[0].name != "" && containsTarget(docs[0].targets, target), "TBD does not support %s: %s", target, path)
	lib := machoLibrary{name: docs[0].name, symbols: map[string]bool{}, current: docs[0].current, compat: docs[0].compat}
	byName := map[string]*tbdDocument{}
	for _, d := range docs {
		check(d.version4 && d.name != "", "incomplete TBD document")
		if tbdTarget(d.name, d.targets, target) {
			byName[d.name] = d
		}
	}
	visited := map[string]bool{}
	var visit func(*tbdDocument)
	visit = func(d *tbdDocument) {
		if visited[d.name] {
			return
		}
		visited[d.name] = true
		for _, g := range append(append([]tbdGroup{}, d.exports...), d.reexports...) {
			if !tbdTarget(d.name, g.targets, target) {
				continue
			}
			for field, names := range g.fields {
				for _, name := range names {
					switch field {
					case "symbols", "weak-symbols", "weak-def-symbols":
						lib.symbols[name] = true
					case "objc-classes":
						lib.symbols["_OBJC_CLASS_$_"+name] = true
						lib.symbols["_OBJC_METACLASS_$_"+name] = true
					case "objc-eh-types":
						lib.symbols["_OBJC_EHTYPE_$_"+name] = true
					case "objc-ivars":
						lib.symbols["_OBJC_IVAR_$_"+name] = true
					case "thread-local-symbols": // TLS imports are rejected by relocation processing.
					default:
						check(false, "unsupported TBD symbol field %s", field)
					}
				}
			}
		}
		for _, g := range d.children {
			if tbdTarget(d.name, g.targets, target) {
				for _, name := range g.fields["libraries"] {
					if child := byName[name]; child != nil {
						visit(child)
					} else {
						lib.reexports = append(lib.reexports, name)
					}
				}
			}
		}
	}
	visit(docs[0])
	return lib
}

func containsTarget(targets []string, target string) bool {
	for _, t := range targets {
		if t == target {
			return true
		}
	}
	return false
}

// Xcode simulator libSystem embeds three host-library documents with macOS
// platform tags. LLD 22.1.8 InputFiles.cpp skipPlatformChecks documents this SDK
// defect. Restrict compatibility to those exact ARM64 simulator reexports.
func tbdTarget(name string, targets []string, target string) bool {
	if containsTarget(targets, target) {
		return true
	}
	if target != "arm64-ios-simulator" || !containsTarget(targets, "arm64-macos") {
		return false
	}
	switch name {
	case "/usr/lib/system/libsystem_kernel.dylib", "/usr/lib/system/libsystem_platform.dylib", "/usr/lib/system/libsystem_pthread.dylib":
		return true
	}
	return false
}
func tbdScalar(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "'") {
		check(len(s) >= 2 && s[len(s)-1] == '\'', "invalid TBD quote")
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	check(!strings.ContainsAny(s, "\"\n\r\t{}&*!"), "unsupported TBD scalar %q", s)
	return s
}
func flowChunkComplete(s string, quoted *bool) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			if *quoted && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			*quoted = !*quoted
		}
		if s[i] == ']' && !*quoted {
			return true
		}
	}
	return false
}
func tbdList(s string) []string {
	s = strings.TrimSpace(s)
	check(strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"), "unsupported TBD list %q", s)
	var out []string
	start := 1
	quoted := false
	for i := 1; i < len(s); i++ {
		if s[i] == '\'' {
			if quoted && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			quoted = !quoted
		}
		if (s[i] == ',' || i == len(s)-1) && !quoted {
			v := strings.TrimSpace(s[start:i])
			if v != "" {
				out = append(out, tbdScalar(v))
			}
			start = i + 1
		}
	}
	check(!quoted, "unterminated TBD string")
	return out
}

func machoVersion(s string) (uint32, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return 0, fmt.Errorf("invalid Mach-O version %q", s)
	}
	var v [3]uint64
	for i, p := range parts {
		bits := 8
		if i == 0 {
			bits = 16
		}
		n, e := strconv.ParseUint(p, 10, bits)
		if e != nil {
			return 0, fmt.Errorf("invalid Mach-O version %q", s)
		}
		v[i] = n
	}
	return uint32(v[0]<<16 | v[1]<<8 | v[2]), nil
}
