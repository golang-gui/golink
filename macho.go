package golink

import (
	"bytes"
	"debug/macho"
	"os"
	"sort"
	"strings"
)

const machoBase uint64 = 0x100000000

type mSection struct {
	seg, name                  string
	flags                      uint32
	alignment, size, addr, off uint64
	data                       []byte
	index, segIndex            int
	reserved1, reserved2       uint32
}
type mPart struct {
	out                     *mSection
	offset, inputAddr, size uint64
}

func (p *mPart) addr() uint64 { return p.out.addr + p.offset }

type mSymbol struct {
	macho.Symbol
	part               *mPart
	got, stub, ordinal int
	imported, absolute bool
}

func (s *mSymbol) value() uint64 {
	if s.absolute {
		return s.Value
	}
	check(s.part != nil, "missing Mach-O section: %s", s.Name)
	return s.part.addr() + s.Value
}

type mObject struct {
	name    string
	parts   []*mPart
	symbols []*mSymbol
}
type mRelocation struct {
	part             *mPart
	off              uint64
	typ, len         uint8
	symbol, subtract *mSymbol
	targetPart       *mPart
	add              int64
}
type mFixup struct {
	section *mSection
	off     uint64
	symbol  *mSymbol
	add     int64
}
type mLinker struct {
	r                                                                        Request
	sections                                                                 []*mSection
	bySection                                                                map[string]*mSection
	objects                                                                  []*mObject
	globals                                                                  map[string]*mSymbol
	relocs                                                                   []mRelocation
	libraries                                                                []machoLibrary
	gotSymbols, stubSymbols, imports, exports                                []*mSymbol
	got, stubs, unwind                                                       *mSection
	compact                                                                  []*mSection
	fixups                                                                   []mFixup
	textEnd, constStart, constEnd, dataStart, dataFileEnd, dataEnd, linkedit uint64
}

func linkMachO(r Request) []byte {
	l := &mLinker{r: r, bySection: map[string]*mSection{}, globals: map[string]*mSymbol{}}
	target := "arm64-ios"
	if r.IOS.Variant == "simulator" {
		target += "-simulator"
	}
	seen := map[string]bool{}
	available := map[string]machoLibrary{}
	byPath := map[string]machoLibrary{}
	for _, p := range append(append([]string{}, r.Libraries...), r.Reexports...) {
		lib := readTBD(p, target)
		available[lib.name] = lib
		byPath[p] = lib
	}
	// Supplemental inputs never become implicit root load commands.
	l.libraries = nil
	seen = map[string]bool{}
	for _, p := range r.Libraries {
		lib := byPath[p]
		if seen[lib.name] {
			continue
		}
		seen[lib.name] = true
		visited := map[string]bool{}
		var collect func(machoLibrary)
		collect = func(child machoLibrary) {
			if visited[child.name] {
				return
			}
			visited[child.name] = true
			for name := range child.symbols {
				lib.symbols[name] = true
			}
			for _, name := range child.reexports {
				next, ok := available[name]
				check(ok, "missing explicit reexport input %s", name)
				collect(next)
			}
		}
		collect(lib)
		l.libraries = append(l.libraries, lib)
	}
	for _, p := range r.Archives {
		for _, m := range readNativeArchive(p) {
			l.load(m.name, m.data)
		}
	}
	for _, p := range r.Objects {
		b, e := os.ReadFile(p)
		check(e == nil, "read Mach-O %s: %v", p, e)
		l.load(p, b)
	}
	l.prepare()
	l.layout()
	l.relocate()
	l.finishUnwind()
	return l.emitMachO()
}
func (l *mLinker) section(seg, name string, flags uint32, alignment uint64) *mSection {
	key := seg + "," + name
	if s := l.bySection[key]; s != nil {
		check(s.flags&255 == flags&255, "incompatible Mach-O section types %s", key)
		s.flags |= flags
		s.alignment = max(s.alignment, alignment)
		return s
	}
	s := &mSection{seg: seg, name: name, flags: flags, alignment: alignment}
	l.bySection[key] = s
	l.sections = append(l.sections, s)
	return s
}
func (l *mLinker) load(name string, b []byte) {
	f, err := macho.NewFile(bytes.NewReader(b))
	check(err == nil, "read Mach-O %s: %v", name, err)
	defer f.Close()
	check(f.Magic == macho.Magic64 && f.Cpu == macho.CpuArm64 && f.Type == macho.TypeObj, "unsupported Mach-O object %s", name)
	check(f.SubCpu&0xffffff == 0, "unsupported Mach-O CPU subtype %d", f.SubCpu)
	minimum, _ := machoVersion(l.r.IOS.MinimumVersion)
	platform := uint32(2)
	if l.r.IOS.Variant == "simulator" {
		platform = 7
	}
	for _, load := range f.Loads {
		raw := load.Raw()
		if len(raw) >= 24 && le.Uint32(raw) == 0x32 {
			check(le.Uint32(raw[8:]) == platform, "Mach-O object platform mismatch %s", name)
			check(le.Uint32(raw[12:]) <= minimum, "Mach-O object requires newer deployment version %s", name)
		}
	}
	check(f.Symtab != nil, "Mach-O object has no symbol table %s", name)
	o := &mObject{name: name, parts: make([]*mPart, len(f.Sections)+1)}
	l.objects = append(l.objects, o)
	for i, s := range f.Sections {
		if s.Seg == "__DWARF" || s.Seg == "__LLVM" {
			continue
		}
		check(s.Align <= 16 && s.Size <= 512<<20, "Mach-O section too large/aligned: %s", s.Name)
		kind := s.Flags & 255
		check(kind != 1 || s.Seg == "__DATA", "zero-fill outside Mach-O DATA segment")
		check(kind == 0 || kind == 1 || kind == 2 || kind == 9 || kind == 10 || kind == 11, "unsupported Mach-O section kind %#x: %s,%s", kind, s.Seg, s.Name)
		var out *mSection
		if s.Seg == "__LD" && s.Name == "__compact_unwind" {
			out = &mSection{seg: s.Seg, name: s.Name, flags: s.Flags, alignment: 1 << s.Align}
			l.compact = append(l.compact, out)
		} else {
			check(s.Seg == "__TEXT" || s.Seg == "__DATA_CONST" || s.Seg == "__DATA", "unsupported Mach-O segment %s", s.Seg)
			out = l.section(s.Seg, s.Name, s.Flags, 1<<s.Align)
		}
		offset := align(out.size, 1<<s.Align)
		check(offset+s.Size <= 512<<20, "merged Mach-O section too large")
		out.size = offset + s.Size
		if kind != 1 {
			data, e := s.Data()
			check(e == nil && uint64(len(data)) == s.Size, "truncated Mach-O section %s", s.Name)
			out.data = append(out.data, make([]byte, int(out.size)-len(out.data))...)
			copy(out.data[offset:], data)
		}
		o.parts[i+1] = &mPart{out: out, offset: offset, inputAddr: s.Addr, size: s.Size}
	}
	for _, s := range f.Symtab.Syms {
		check(s.Type&0xe0 == 0, "unsupported Mach-O STAB symbol %s", s.Name)
		kind := s.Type & 14
		check(kind == 0 || kind == 2 || kind == 14, "unsupported Mach-O symbol kind %s", s.Name)
		v := &mSymbol{Symbol: s, got: -1, stub: -1, absolute: kind == 2}
		if kind == 14 {
			check(int(s.Sect) < len(o.parts), "Mach-O symbol section out of range %s", s.Name)
			v.part = o.parts[s.Sect]
			if v.part != nil {
				check(s.Value >= v.part.inputAddr && s.Value-v.part.inputAddr <= v.part.size, "Mach-O symbol outside section %s", s.Name)
				v.Value -= v.part.inputAddr
			}
		}
		o.symbols = append(o.symbols, v)
		if s.Type&1 == 0 || s.Name == "" {
			continue
		}
		previous := l.globals[s.Name]
		defined := kind != 0 || s.Value != 0
		if previous == nil {
			l.globals[s.Name] = v
			continue
		}
		prevDefined := previous.Type&14 != 0 || previous.Value != 0
		if !prevDefined && defined || !prevDefined && !defined && previous.Desc&0x40 != 0 && s.Desc&0x40 == 0 || prevDefined && defined && previous.Desc&0x80 != 0 && s.Desc&0x80 == 0 {
			l.globals[s.Name] = v
		} else if defined && prevDefined && previous.Desc&0x80 == 0 && s.Desc&0x80 == 0 {
			check(false, "duplicate Mach-O symbol %s", s.Name)
		}
	}
	for i, s := range f.Sections {
		part := o.parts[i+1]
		if part == nil {
			continue
		}
		pending := int64(0)
		for j := 0; j < len(s.Relocs); j++ {
			r := s.Relocs[j]
			check(!r.Scattered, "scattered Mach-O relocation")
			if r.Type == 10 {
				check(j+1 < len(s.Relocs) && s.Relocs[j+1].Addr == r.Addr, "orphan Mach-O addend")
				pending = int64(int32(r.Value<<8) >> 8)
				continue
			}
			width := uint64(1) << r.Len
			check(uint64(r.Addr) <= part.size && width <= part.size-uint64(r.Addr), "Mach-O relocation outside section")
			rel := mRelocation{part: part, off: uint64(r.Addr), typ: r.Type, len: r.Len, add: pending}
			pending = 0
			if r.Extern {
				check(int(r.Value) < len(o.symbols), "Mach-O relocation symbol out of range")
				rel.symbol = o.symbols[r.Value]
			} else {
				check(int(r.Value) < len(o.parts), "Mach-O relocation section out of range")
				rel.targetPart = o.parts[r.Value]
			}
			if r.Type == 1 {
				check(r.Extern && j+1 < len(s.Relocs), "invalid Mach-O subtractor")
				pair := s.Relocs[j+1]
				j++
				check(pair.Type == 0 && pair.Addr == r.Addr && pair.Extern && pair.Len == r.Len && int(pair.Value) < len(o.symbols), "invalid Mach-O subtractor pair")
				rel.subtract = rel.symbol
				rel.symbol = o.symbols[pair.Value]
			}
			check((r.Type == 0 || r.Type == 1) && r.Len == 3 && !r.Pcrel || (r.Type >= 2 && r.Type <= 6) && r.Len == 2 && r.Extern, "unsupported Mach-O relocation type/width %d/%d", r.Type, r.Len)
			l.relocs = append(l.relocs, rel)
		}
		check(pending == 0, "trailing Mach-O addend")
	}
}
func (l *mLinker) canonical(s *mSymbol) *mSymbol {
	if s != nil && s.Type&1 != 0 && s.Name != "" {
		return l.globals[s.Name]
	}
	return s
}
func (l *mLinker) gotFor(s *mSymbol) {
	if s.got < 0 {
		s.got = len(l.gotSymbols)
		l.gotSymbols = append(l.gotSymbols, s)
	}
}
func (l *mLinker) prepare() {
	names := make([]string, 0, len(l.globals))
	for name := range l.globals {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s := l.globals[name]
		if s.Type&14 == 0 && s.Value != 0 {
			section := l.section("__DATA", "__common", 1, 16)
			off := align(section.size, 16)
			section.size = off + s.Value
			s.part = &mPart{out: section, offset: off, size: s.Value}
			s.Value = 0
			s.Type = s.Type&^14 | 14
		}
		if s.Type&14 == 0 {
			for i, lib := range l.libraries {
				if lib.symbols[name] {
					s.imported = true
					s.ordinal = i + 1
					break
				}
			}
			if !s.imported {
				check(s.Desc&0x40 != 0, "unresolved Mach-O symbol %s", name)
				s.absolute = true
				s.Value = 0
				continue
			}
			l.imports = append(l.imports, s)
		} else if s.part != nil && s.Type&0x10 == 0 {
			l.exports = append(l.exports, s)
		}
	}
	for i := range l.relocs {
		r := &l.relocs[i]
		r.symbol = l.canonical(r.symbol)
		r.subtract = l.canonical(r.subtract)
		if r.typ == 5 || r.typ == 6 {
			l.gotFor(r.symbol)
		}
		if r.typ == 2 && r.symbol.imported {
			if r.symbol.stub < 0 {
				r.symbol.stub = len(l.stubSymbols)
				l.stubSymbols = append(l.stubSymbols, r.symbol)
			}
			l.gotFor(r.symbol)
		}
		if r.typ == 3 || r.typ == 4 {
			check(!r.symbol.imported, "direct address to imported Mach-O symbol %s", r.symbol.Name)
		}
		if r.typ == 0 && r.part.out.seg == "__TEXT" {
			check(r.part.out.name != "__text", "Mach-O text pointer relocation")
			r.part.out.seg = "__DATA_CONST"
		}
	}
	l.got = l.section("__DATA_CONST", "__got", 6, 8)
	l.got.size = uint64(len(l.gotSymbols) * 8)
	l.got.data = make([]byte, l.got.size)
	l.stubs = l.section("__TEXT", "__stubs", 0x80000408, 4)
	l.stubs.size = uint64(len(l.stubSymbols) * 12)
	l.stubs.data = make([]byte, l.stubs.size)
	l.stubs.reserved2 = 12
	count := uint64(0)
	for _, c := range l.compact {
		check(c.size%32 == 0, "invalid compact unwind length")
		count += c.size / 32
	}
	l.unwind = l.section("__TEXT", "__unwind_info", 0, 4)
	l.unwind.size = 28 + 24 + 8 + count*8
	l.unwind.data = make([]byte, l.unwind.size)
}
func (l *mLinker) layout() {
	cursor := uint64(16384)
	place := func(seg string, zero bool) {
		for _, s := range l.sections {
			if s.seg != seg || (s.flags&255 == 1) != zero {
				continue
			}
			cursor = align(cursor, s.alignment)
			s.off = cursor
			s.addr = machoBase + cursor
			cursor += s.size
			check(cursor < 1<<30, "Mach-O output exceeds 1 GiB")
		}
	}
	place("__TEXT", false)
	l.textEnd = align(cursor, page)
	cursor = l.textEnd
	l.constStart = cursor
	place("__DATA_CONST", false)
	l.constEnd = align(cursor, page)
	cursor = l.constEnd
	l.dataStart = cursor
	place("__DATA", false)
	l.dataFileEnd = cursor
	place("__DATA", true)
	l.dataEnd = align(cursor, page)
	l.linkedit = l.dataEnd
	index := 1
	for segIndex, seg := range []string{"__PAGEZERO", "__TEXT", "__DATA_CONST", "__DATA", "__LINKEDIT"} {
		for _, s := range l.sections {
			if s.seg == seg {
				check(index < 256, "too many Mach-O sections")
				s.index = index
				s.segIndex = segIndex
				index++
			}
		}
	}
}
func (l *mLinker) relocate() {
	for _, s := range l.gotSymbols {
		off := uint64(s.got * 8)
		if s.imported {
			l.fixups = append(l.fixups, mFixup{l.got, off, s, 0})
		} else {
			le.PutUint64(l.got.data[off:], s.value())
			if !s.absolute {
				l.fixups = append(l.fixups, mFixup{l.got, off, nil, 0})
			}
		}
	}
	for _, s := range l.stubSymbols {
		p := l.stubs.data[s.stub*12:]
		addr := l.stubs.addr + uint64(s.stub*12)
		got := l.got.addr + uint64(s.got*8)
		machoADRP(p, got, addr)
		le.PutUint32(p[4:], 0xf9400210|uint32((got&4095)/8)<<10)
		le.PutUint32(p[8:], 0xd61f0200)
	}
	for _, r := range l.relocs {
		off := r.part.offset + r.off
		p := r.part.out.data[off:]
		place := r.part.addr() + r.off
		target := uint64(0)
		absolute := false
		if r.symbol != nil && !r.symbol.imported {
			target = r.symbol.value()
			absolute = r.symbol.absolute
		}
		switch r.typ {
		case 0:
			add := int64(le.Uint64(p)) + r.add
			if r.symbol == nil {
				if r.targetPart == nil {
					absolute = true
					target = uint64(add)
				} else {
					target = r.targetPart.addr() + uint64(add) - r.targetPart.inputAddr
				}
			} else if r.symbol.imported {
				check(r.part.out.seg != "__LD", "imported unwind pointer")
				l.fixups = append(l.fixups, mFixup{r.part.out, off, r.symbol, add})
				continue
			} else {
				target += uint64(add)
			}
			le.PutUint64(p, target)
			if !absolute && r.part.out.seg != "__LD" {
				check(r.part.out.seg != "__TEXT", "text rebase")
				l.fixups = append(l.fixups, mFixup{r.part.out, off, nil, 0})
			}
		case 1:
			check(!r.symbol.imported && !r.subtract.imported, "imported Mach-O subtractor")
			le.PutUint64(p, target-r.subtract.value()+le.Uint64(p))
		case 2:
			if r.symbol.imported {
				target = l.stubs.addr + uint64(r.symbol.stub*12)
			}
			word := le.Uint32(p)
			add := int64(int32(word<<6) >> 4)
			delta := int64(target) + add + r.add - int64(place)
			check(delta%4 == 0 && delta >= -1<<27 && delta < 1<<27, "Mach-O branch overflow %s", r.symbol.Name)
			le.PutUint32(p, word&0xfc000000|uint32(delta>>2)&0x3ffffff)
		case 3, 5:
			if r.typ == 5 {
				target = l.got.addr + uint64(r.symbol.got*8)
			}
			word := le.Uint32(p)
			imm := (word >> 29 & 3) | (word>>5&0x7ffff)<<2
			add := int64(int32(imm<<11)>>11) << 12
			target = uint64(int64(target) + add + r.add)
			machoADRP(p, target, place)
		case 4, 6:
			if r.typ == 6 {
				target = l.got.addr + uint64(r.symbol.got*8)
			}
			word := le.Uint32(p)
			scale := uint(0)
			if word&0x3b000000 == 0x39000000 {
				scale = uint(word >> 30)
				if word&0x04800000 == 0x04800000 {
					scale = 4
				}
			}
			add := int64((word >> 10 & 4095) << scale)
			value := uint64(int64(target)+add+r.add) & 4095
			check(value&((1<<scale)-1) == 0, "unaligned Mach-O page offset")
			le.PutUint32(p, word&^uint32(0x003ffc00)|uint32(value>>scale)<<10)
		}
	}
}
func machoADRP(p []byte, target, place uint64) {
	d := int64(target>>12) - int64(place>>12)
	check(d >= -1<<20 && d < 1<<20, "Mach-O ADRP overflow")
	word := le.Uint32(p)
	if word == 0 {
		word = 0x90000010
	}
	v := uint32(d) & 0x1fffff
	le.PutUint32(p, word&^uint32(0x60ffffe0)|(v&3)<<29|(v>>2)<<5)
}
func (l *mLinker) finishUnwind() {
	type entry struct{ function, length, encoding uint32 }
	var entries []entry
	for _, s := range l.compact {
		for p := 0; p < len(s.data); p += 32 {
			b := s.data[p:]
			function := le.Uint64(b)
			encoding := le.Uint32(b[12:])
			check(le.Uint64(b[16:]) == 0 && le.Uint64(b[24:]) == 0, "unwind personality/LSDA unsupported")
			if encoding&0x0f000000 == 0x03000000 {
				encoding |= l.dwarfFDE(function)
			}
			entries = append(entries, entry{uint32(function - machoBase), le.Uint32(b[8:]), encoding})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].function < entries[j].function })
	b := l.unwind.data
	le.PutUint32(b, 1)
	le.PutUint32(b[4:], 28)
	le.PutUint32(b[12:], 28)
	le.PutUint32(b[20:], 28)
	le.PutUint32(b[24:], 2)
	if len(entries) == 0 {
		return
	}
	le.PutUint32(b[28:], entries[0].function)
	le.PutUint32(b[32:], 52)
	le.PutUint32(b[40:], entries[len(entries)-1].function+entries[len(entries)-1].length)
	le.PutUint32(b[52:], 2)
	le.PutUint16(b[56:], 8)
	check(len(entries) <= 65535, "too many compact unwind entries")
	le.PutUint16(b[58:], uint16(len(entries)))
	for i, e := range entries {
		le.PutUint32(b[60+i*8:], e.function)
		le.PutUint32(b[64+i*8:], e.encoding)
	}
}
func (l *mLinker) dwarfFDE(function uint64) uint32 {
	for _, s := range l.sections {
		if s.name != "__eh_frame" {
			continue
		}
		encodings := map[int]byte{}
		for p := 0; p+8 <= len(s.data); {
			n := int(le.Uint32(s.data[p:]))
			if n == 0 {
				p += 4
				continue
			}
			check(n >= 4 && p+4+n <= len(s.data), "bad Mach-O EH frame")
			id := le.Uint32(s.data[p+4:])
			end := p + 4 + n
			if id == 0 {
				q := p + 8
				check(q < end, "truncated Mach-O CIE")
				version := s.data[q]
				q++
				check(version == 1 || version == 3, "unsupported Mach-O CIE version")
				a := q
				for q < end && s.data[q] != 0 {
					q++
				}
				check(q < end, "truncated Mach-O CIE augmentation")
				aug := string(s.data[a:q])
				q++
				uleb(s.data[:end], &q)
				uleb(s.data[:end], &q)
				if version == 1 {
					q++
				} else {
					uleb(s.data[:end], &q)
				}
				check(q <= end && aug == "zR", "unsupported Mach-O CIE augmentation")
				length := uleb(s.data[:end], &q)
				check(length == 1 && q < end, "unsupported Mach-O CIE encoding length")
				encodings[p] = s.data[q]
			} else {
				encoding, ok := encodings[p+4-int(id)]
				check(ok, "unknown Mach-O CIE")
				check(encoding == 0x10 && n >= 20, "unsupported Mach-O FDE encoding %#x", encoding)
				pc := uint64(int64(s.addr+uint64(p+8)) + int64(le.Uint64(s.data[p+8:])))
				if pc == function {
					check(p < 1<<24, "FDE offset overflow")
					return uint32(p)
				}
			}
			p += 4 + n
		}
	}
	check(false, "missing DWARF FDE for %#x", function)
	return 0
}

// Preserve the native segment/section names used by dyld and Objective-C.
func mName(b []byte, s string) {
	check(len(s) <= 16 && !strings.ContainsRune(s, 0), "invalid Mach-O name %s", s)
	copy(b, s)
}
func mWords(words ...uint32) []byte {
	b := make([]byte, len(words)*4)
	for i, v := range words {
		le.PutUint32(b[i*4:], v)
	}
	return b
}
func mStringCommand(cmd uint32, s string, header int) []byte {
	b := make([]byte, align(uint64(header+len(s)+1), 8))
	le.PutUint32(b, cmd)
	le.PutUint32(b[4:], uint32(len(b)))
	le.PutUint32(b[8:], uint32(header))
	copy(b[header:], s)
	return b
}
