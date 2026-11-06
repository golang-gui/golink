package golink

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

var le = binary.LittleEndian

const page uint64 = 16384
const (
	readOnly = iota
	textCode
	relro
	initArray
	finiArray
	mutable
	bss
)

type section struct {
	name              string
	typ               elf.SectionType
	flags             elf.SectionFlag
	align, size, addr uint64
	data              []byte
	role, index       int
	link, info        uint32
	entsize           uint64
}
type symbol struct {
	elf.Symbol
	sec      *section
	absolute bool
	imported bool
	dynIndex uint32
	got, plt int
	owner    *object
}
type relocation struct {
	sec *section
	off uint64
	typ elf.R_AARCH64
	sym *symbol
	add int64
}
type object struct {
	name     string
	sections map[int]*section
	symbols  []*symbol
}
type dynrel struct {
	off uint64
	typ elf.R_AARCH64
	sym *symbol
	add int64
}
type linker struct {
	sections                                                      []*section
	objects                                                       []*object
	globals                                                       map[string]*symbol
	rels                                                          []relocation
	imports, exports                                              []*symbol
	gotSyms, pltSyms                                              []*symbol
	dynamicRels                                                   []dynrel
	libs                                                          []string
	libSymbols                                                    map[string]bool
	str                                                           []byte
	strOffsets                                                    map[string]uint32
	dynstr, dynsym, hash, rela, got, plt, dynamic, ehhdr          *section
	roEnd, textStart, textEnd, rwStart, relroEnd, fileEnd, memEnd uint64
	phnum                                                         int
	loadedArchives                                                int
	entryName                                                     string
	soname                                                        string
	symbolic, nodelete                                            bool
	interp                                                        *section
}

func align(v, n uint64) uint64 {
	if n == 0 {
		n = 1
	}
	check(n&(n-1) == 0 && n <= 65536 && v <= (1<<30)-n, "unsupported output size/alignment")
	return (v + n - 1) &^ (n - 1)
}
func check(ok bool, format string, args ...any) {
	if !ok {
		panic(linkError{fmt.Errorf(format, args...)})
	}
}
func (l *linker) add(s *section) *section {
	s.index = len(l.sections) + 1
	l.sections = append(l.sections, s)
	return s
}
func (l *linker) generated(name string, typ elf.SectionType, flags elf.SectionFlag, alignment, size uint64, role int) *section {
	return l.add(&section{name: name, typ: typ, flags: flags, align: alignment, size: size, data: make([]byte, size), role: role})
}
func (l *linker) load(name string, data []byte) {
	f, err := elf.NewFile(bytes.NewReader(data))
	check(err == nil, "read %s: %v", name, err)
	defer f.Close()
	check(f.Class == elf.ELFCLASS64 && f.Data == elf.ELFDATA2LSB && f.Machine == elf.EM_AARCH64 && f.Type == elf.ET_REL, "unsupported object %s", name)
	check(len(l.sections)+len(f.Sections) < int(elf.SHN_LORESERVE), "too many output sections")
	obj := &object{name: name, sections: map[int]*section{}}
	l.objects = append(l.objects, obj)
	for i, s := range f.Sections {
		if s.Flags&elf.SHF_ALLOC == 0 {
			continue
		}
		check(s.Flags&elf.SHF_TLS == 0, "TLS sections not supported: %s:%s", name, s.Name)
		check(s.Flags&(elf.SHF_COMPRESSED|elf.SHF_GROUP|elf.SHF_LINK_ORDER) == 0, "unsupported section flags: %s:%s", name, s.Name)
		check(s.Size <= 512<<20, "section too large: %s:%s", name, s.Name)
		check(s.Type == elf.SHT_PROGBITS || s.Type == elf.SHT_NOBITS || s.Type == elf.SHT_INIT_ARRAY || s.Type == elf.SHT_FINI_ARRAY || s.Type == elf.SHT_NOTE, "unsupported loadable section %s:%s", name, s.Name)
		check(s.Addralign == 0 || s.Addralign&(s.Addralign-1) == 0, "bad alignment")
		role := readOnly
		if s.Type == elf.SHT_NOBITS {
			role = bss
		} else if s.Flags&elf.SHF_EXECINSTR != 0 {
			role = textCode
		} else if s.Type == elf.SHT_INIT_ARRAY {
			role = initArray
		} else if s.Type == elf.SHT_FINI_ARRAY {
			role = finiArray
		} else if strings.HasPrefix(s.Name, ".data.rel.ro") {
			role = relro
		} else if s.Flags&elf.SHF_WRITE != 0 {
			role = mutable
		}
		var body []byte
		if s.Type != elf.SHT_NOBITS {
			body, err = s.Data()
			check(err == nil, "section %s: %v", s.Name, err)
			check(uint64(len(body)) == s.Size, "truncated section %s:%s", name, s.Name)
			body = append([]byte(nil), body...)
		}
		out := l.add(&section{name: fmt.Sprintf("%s.%d", s.Name, len(l.objects)-1), typ: s.Type, flags: s.Flags, align: s.Addralign, size: s.Size, data: body, role: role})
		obj.sections[i] = out
	}
	raw, err := f.Symbols()
	check(err == nil, "symbols %s: %v", name, err)
	obj.symbols = append(obj.symbols, &symbol{absolute: true, got: -1, plt: -1, owner: obj})
	for _, s := range raw {
		check(s.Section == elf.SHN_UNDEF || s.Section == elf.SHN_ABS || s.Section == elf.SHN_COMMON || int(s.Section) < len(f.Sections), "invalid symbol section: %s", s.Name)
		v := &symbol{Symbol: s, sec: obj.sections[int(s.Section)], absolute: s.Section == elf.SHN_ABS, got: -1, plt: -1, owner: obj}
		obj.symbols = append(obj.symbols, v)
		bind := elf.ST_BIND(s.Info)
		if bind == elf.STB_LOCAL || s.Name == "" {
			continue
		}
		check(bind == elf.STB_GLOBAL || bind == elf.STB_WEAK, "unsupported binding: %s", s.Name)
		prev := l.globals[s.Name]
		defined := s.Section != elf.SHN_UNDEF
		if s.Section == elf.SHN_COMMON && prev != nil && prev.Section != elf.SHN_UNDEF {
			if prev.Section == elf.SHN_COMMON {
				if s.Size > prev.Size {
					prev.Size = s.Size
				}
				if s.Value > prev.Value {
					prev.Value = s.Value
				}
			}
			continue
		}
		if prev != nil && prev.Section == elf.SHN_COMMON && defined && s.Section != elf.SHN_COMMON {
			l.globals[s.Name] = v
			continue
		}
		if prev == nil || prev.Section == elf.SHN_UNDEF && defined || prev.Section == elf.SHN_UNDEF && elf.ST_BIND(prev.Info) == elf.STB_WEAK && bind == elf.STB_GLOBAL || prev.Section != elf.SHN_UNDEF && elf.ST_BIND(prev.Info) == elf.STB_WEAK && defined && bind == elf.STB_GLOBAL {
			l.globals[s.Name] = v
		} else if defined && prev.Section != elf.SHN_UNDEF && bind == elf.STB_GLOBAL && elf.ST_BIND(prev.Info) == elf.STB_GLOBAL {
			check(false, "duplicate symbol %s", s.Name)
		}
	}
	for _, s := range f.Sections {
		if s.Type != elf.SHT_RELA {
			continue
		}
		dest := obj.sections[int(s.Info)]
		if dest == nil {
			continue
		}
		body, err := s.Data()
		check(err == nil && len(body)%24 == 0, "bad relocations %s", name)
		for p := 0; p < len(body); p += 24 {
			info := le.Uint64(body[p+8:])
			index := uint32(info >> 32)
			check(int(index) < len(obj.symbols), "bad symbol index")
			offset, typ := le.Uint64(body[p:]), elf.R_AARCH64(uint32(info))
			width := uint64(4)
			if typ == elf.R_AARCH64_ABS64 {
				width = 8
			} else if typ == elf.R_AARCH64_NONE {
				width = 0
			}
			check(offset <= uint64(len(dest.data)) && width <= uint64(len(dest.data))-offset, "relocation outside section %s:%s", name, dest.name)
			l.rels = append(l.rels, relocation{dest, offset, typ, obj.symbols[index], int64(le.Uint64(body[p+16:]))})
		}
	}
}
func (l *linker) canonical(s *symbol) *symbol {
	if elf.ST_BIND(s.Info) != elf.STB_LOCAL && s.Name != "" {
		return l.globals[s.Name]
	}
	return s
}
func (l *linker) strAdd(s string) uint32 {
	if v, ok := l.strOffsets[s]; ok {
		return v
	}
	v := uint32(len(l.str))
	l.strOffsets[s] = v
	l.str = append(l.str, []byte(s)...)
	l.str = append(l.str, 0)
	return v
}
func (l *linker) gotFor(s *symbol) uint64 {
	if s.got < 0 {
		s.got = len(l.gotSyms)
		l.gotSyms = append(l.gotSyms, s)
	}
	return uint64(s.got) * 8
}
func gnuHash(s string) uint32 {
	h := uint32(5381)
	for i := 0; i < len(s); i++ {
		h = h*33 + uint32(s[i])
	}
	return h
}
func (l *linker) prepare() {
	if l.entryName != "" {
		l.interp = l.generated(".interp", elf.SHT_PROGBITS, elf.SHF_ALLOC, 1, 20, readOnly)
		l.interp.data = []byte("/system/bin/linker64\x00")
		l.interp.size = uint64(len(l.interp.data))
	}
	commonNames := make([]string, 0, len(l.globals))
	for name := range l.globals {
		commonNames = append(commonNames, name)
	}
	sort.Strings(commonNames)
	for _, name := range commonNames {
		s := l.globals[name]
		if s.Section == elf.SHN_COMMON {
			s.sec = l.generated(".common."+s.Name, elf.SHT_NOBITS, elf.SHF_ALLOC|elf.SHF_WRITE, s.Value, 0, bss)
			s.sec.size = s.Size
			s.Section = elf.SectionIndex(s.sec.index)
			s.Value = 0
		}
	}
	names := make([]string, 0, len(l.globals))
	for name := range l.globals {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s := l.globals[name]
		if s.Section == elf.SHN_UNDEF {
			if !l.libSymbols[name] {
				check(elf.ST_BIND(s.Info) == elf.STB_WEAK, "unresolved symbol %s", name)
				s.absolute = true
				s.Value = 0
				continue
			}
			s.imported = true
			l.imports = append(l.imports, s)
		} else if s.sec != nil && (s.Other&3) == 0 {
			l.exports = append(l.exports, s)
		}
	}
	buckets := len(l.exports) / 4
	if buckets < 1 {
		buckets = 1
	}
	sort.SliceStable(l.exports, func(i, j int) bool {
		a, b := gnuHash(l.exports[i].Name)%uint32(buckets), gnuHash(l.exports[j].Name)%uint32(buckets)
		if a != b {
			return a < b
		}
		return l.exports[i].Name < l.exports[j].Name
	})
	for i := range l.rels {
		r := &l.rels[i]
		r.sym = l.canonical(r.sym)
		s := r.sym
		switch r.typ {
		case elf.R_AARCH64_NONE, elf.R_AARCH64_PREL32, elf.R_AARCH64_ADR_PREL_PG_HI21, elf.R_AARCH64_ADD_ABS_LO12_NC, elf.R_AARCH64_LDST8_ABS_LO12_NC, elf.R_AARCH64_LDST16_ABS_LO12_NC, elf.R_AARCH64_LDST32_ABS_LO12_NC, elf.R_AARCH64_LDST64_ABS_LO12_NC, elf.R_AARCH64_LDST128_ABS_LO12_NC:
			check(!s.imported, "direct address to imported symbol %s", s.Name)
		case elf.R_AARCH64_ABS64:
			check(r.sec.role != textCode, "text relocation to %s", s.Name)
			if r.sec.role == readOnly {
				r.sec.role = relro
				r.sec.flags |= elf.SHF_WRITE
			}
		case elf.R_AARCH64_CALL26, elf.R_AARCH64_JUMP26:
			if s.imported {
				if s.plt < 0 {
					s.plt = len(l.pltSyms)
					l.pltSyms = append(l.pltSyms, s)
				}
				l.gotFor(s)
			}
		case elf.R_AARCH64_ADR_GOT_PAGE, elf.R_AARCH64_LD64_GOT_LO12_NC:
			l.gotFor(s)
		default:
			check(false, "unsupported relocation %s", r.typ)
		}
	}
	rw := elf.SHF_ALLOC | elf.SHF_WRITE
	ro := elf.SHF_ALLOC
	l.dynstr = l.generated(".dynstr", elf.SHT_STRTAB, ro, 1, 0, readOnly)
	total := 1 + len(l.imports) + len(l.exports)
	l.dynsym = l.generated(".dynsym", elf.SHT_DYNSYM, ro, 8, uint64(total*24), readOnly)
	l.dynsym.link = uint32(l.dynstr.index)
	l.dynsym.info = 1
	l.dynsym.entsize = 24
	l.hash = l.generated(".gnu.hash", elf.SHT_GNU_HASH, ro, 8, uint64(16+8+buckets*4+len(l.exports)*4), readOnly)
	l.hash.link = uint32(l.dynsym.index)
	l.plt = l.generated(".plt", elf.SHT_PROGBITS, ro|elf.SHF_EXECINSTR, 16, uint64(len(l.pltSyms)*16), textCode)
	l.got = l.generated(".got", elf.SHT_PROGBITS, rw, 8, uint64(len(l.gotSyms)*8), relro)
	l.got.entsize = 8
	relcount := 0
	for _, s := range l.gotSyms {
		if !s.absolute {
			relcount++
		}
	}
	for _, r := range l.rels {
		if r.typ == elf.R_AARCH64_ABS64 && !r.sym.absolute {
			relcount++
		}
	}
	l.rela = l.generated(".rela.dyn", elf.SHT_RELA, ro, 8, uint64(relcount*24), readOnly)
	l.rela.link = uint32(l.dynsym.index)
	l.rela.entsize = 24
	l.dynamic = l.generated(".dynamic", elf.SHT_DYNAMIC, rw, 8, uint64((20+len(l.libs))*16), relro)
	l.dynamic.link = uint32(l.dynstr.index)
	l.dynamic.entsize = 16
	fdes := l.countFDE()
	l.ehhdr = l.generated(".eh_frame_hdr", elf.SHT_PROGBITS, ro, 4, uint64(12+fdes*8), readOnly)
	l.str = []byte{0}
	l.strOffsets = map[string]uint32{"": 0}
	for _, s := range append(append([]*symbol{}, l.imports...), l.exports...) {
		l.strAdd(s.Name)
	}
	for _, name := range l.libs {
		l.strAdd(name)
	}
	if l.soname != "" {
		l.strAdd(l.soname)
	}
	l.dynstr.data = l.str
	l.dynstr.size = uint64(len(l.str))
	l.phnum = 8
	if l.interp != nil {
		l.phnum++
	}
	for _, s := range l.sections {
		if s.typ == elf.SHT_NOTE {
			l.phnum++
		}
	}
	cursor := align(uint64(64+56*l.phnum), 16)
	place := func(role int) {
		for _, s := range l.sections {
			if s.role == role {
				cursor = align(cursor, s.align)
				s.addr = cursor
				check(s.size <= (1<<30)-cursor, "output exceeds 1 GiB")
				cursor += s.size
			}
		}
	}
	place(readOnly)
	l.roEnd = cursor
	cursor = align(cursor, page)
	l.textStart = cursor
	place(textCode)
	l.textEnd = cursor
	cursor = align(cursor, page)
	l.rwStart = cursor
	place(relro)
	place(initArray)
	place(finiArray)
	cursor = align(cursor, page)
	l.relroEnd = cursor
	place(mutable)
	l.fileEnd = cursor
	place(bss)
	l.memEnd = cursor
}
func (s *symbol) value() uint64 {
	if s.absolute {
		return s.Value
	}
	check(s.sec != nil, "no section for %s", s.Name)
	return s.sec.addr + s.Value
}
func signed32(v int64) uint32 {
	check(v >= -1<<31 && v < 1<<31, "32-bit overflow: %d", v)
	return uint32(v)
}
func (l *linker) finishTables() {
	all := append(append([]*symbol{}, l.imports...), l.exports...)
	for i, s := range all {
		s.dynIndex = uint32(i + 1)
		p := l.dynsym.data[(i+1)*24:]
		le.PutUint32(p, l.strAdd(s.Name))
		p[4] = s.Info
		p[5] = s.Other
		var ndx uint16
		var value uint64
		if !s.imported {
			ndx = uint16(s.sec.index)
			value = s.value()
		}
		le.PutUint16(p[6:], ndx)
		le.PutUint64(p[8:], value)
		le.PutUint64(p[16:], s.Size)
	}
	h := l.hash.data
	buckets := len(l.exports) / 4
	if buckets < 1 {
		buckets = 1
	}
	offset := uint32(1 + len(l.imports))
	le.PutUint32(h, uint32(buckets))
	le.PutUint32(h[4:], offset)
	le.PutUint32(h[8:], 1)
	le.PutUint32(h[12:], 6)
	var bloom uint64
	for i, s := range l.exports {
		v := gnuHash(s.Name)
		bloom |= 1<<(v%64) | 1<<((v>>6)%64)
		bucket := v % uint32(buckets)
		p := h[24+int(bucket)*4:]
		if le.Uint32(p) == 0 {
			le.PutUint32(p, offset+uint32(i))
		}
		chain := v &^ 1
		if i+1 == len(l.exports) || gnuHash(l.exports[i+1].Name)%uint32(buckets) != bucket {
			chain |= 1
		}
		le.PutUint32(h[24+buckets*4+i*4:], chain)
	}
	le.PutUint64(h[16:], bloom)
	for i, s := range l.gotSyms {
		addr := l.got.addr + uint64(i)*8
		if s.imported {
			l.dynamicRels = append(l.dynamicRels, dynrel{addr, elf.R_AARCH64_GLOB_DAT, s, 0})
		} else if !s.absolute {
			le.PutUint64(l.got.data[i*8:], s.value())
			l.dynamicRels = append(l.dynamicRels, dynrel{addr, elf.R_AARCH64_RELATIVE, nil, int64(s.value())})
		} else {
			le.PutUint64(l.got.data[i*8:], s.Value)
		}
	}
	for i, s := range l.pltSyms {
		addr := l.plt.addr + uint64(i*16)
		got := l.got.addr + uint64(s.got*8)
		p := l.plt.data[i*16:]
		delta := int64(got>>12) - int64(addr>>12)
		check(delta >= -1<<20 && delta < 1<<20, "PLT page out of range")
		word := uint32(delta) & 0x1fffff
		le.PutUint32(p, 0x90000010|((word&3)<<29)|((word>>2)<<5))
		le.PutUint32(p[4:], 0xf9400211|uint32((got&4095)/8)<<10)
		le.PutUint32(p[8:], 0xd61f0220)
		le.PutUint32(p[12:], 0xd503201f)
	}
	for _, r := range l.rels {
		check(r.off <= uint64(len(r.sec.data)), "relocation outside section")
		p := r.sec.data[r.off:]
		place := r.sec.addr + r.off
		s := r.sym
		var target uint64
		if !s.imported {
			target = s.value() + uint64(r.add)
		}
		switch r.typ {
		case elf.R_AARCH64_NONE:
		case elf.R_AARCH64_ABS64:
			if s.imported {
				l.dynamicRels = append(l.dynamicRels, dynrel{place, elf.R_AARCH64_ABS64, s, r.add})
			} else {
				le.PutUint64(p, target)
				if !s.absolute {
					l.dynamicRels = append(l.dynamicRels, dynrel{place, elf.R_AARCH64_RELATIVE, nil, int64(target)})
				}
			}
		case elf.R_AARCH64_PREL32:
			le.PutUint32(p, signed32(int64(target)-int64(place)))
		case elf.R_AARCH64_CALL26, elf.R_AARCH64_JUMP26:
			if s.imported {
				target = l.plt.addr + uint64(s.plt*16) + uint64(r.add)
			}
			d := int64(target) - int64(place)
			check(d%4 == 0 && d >= -1<<27 && d < 1<<27, "branch out of range: %s", s.Name)
			le.PutUint32(p, le.Uint32(p)&0xfc000000|uint32(d>>2)&0x3ffffff)
		case elf.R_AARCH64_ADR_PREL_PG_HI21, elf.R_AARCH64_ADR_GOT_PAGE:
			if r.typ == elf.R_AARCH64_ADR_GOT_PAGE {
				target = l.got.addr + uint64(s.got*8) + uint64(r.add)
			}
			d := int64(target>>12) - int64(place>>12)
			check(d >= -1<<20 && d < 1<<20, "ADRP out of range")
			v := uint32(d) & 0x1fffff
			le.PutUint32(p, le.Uint32(p)&^uint32(0x60ffffe0)|(v&3)<<29|(v>>2)<<5)
		case elf.R_AARCH64_ADD_ABS_LO12_NC:
			le.PutUint32(p, le.Uint32(p)&^uint32(0x003ffc00)|uint32(target&4095)<<10)
		default:
			scale := uint(0)
			switch r.typ {
			case elf.R_AARCH64_LDST16_ABS_LO12_NC:
				scale = 1
			case elf.R_AARCH64_LDST32_ABS_LO12_NC:
				scale = 2
			case elf.R_AARCH64_LDST64_ABS_LO12_NC:
				scale = 3
			case elf.R_AARCH64_LDST128_ABS_LO12_NC:
				scale = 4
			case elf.R_AARCH64_LD64_GOT_LO12_NC:
				scale = 3
				target = l.got.addr + uint64(s.got*8) + uint64(r.add)
			}
			check(target&((1<<scale)-1) == 0, "unaligned load/store %s", s.Name)
			le.PutUint32(p, le.Uint32(p)&^uint32(0x003ffc00)|uint32((target&4095)>>scale)<<10)
		}
	}
	// Android loaders process relative entries first when DT_RELACOUNT is present.
	sort.SliceStable(l.dynamicRels, func(i, j int) bool {
		return l.dynamicRels[i].typ == elf.R_AARCH64_RELATIVE && l.dynamicRels[j].typ != elf.R_AARCH64_RELATIVE
	})
	check(len(l.dynamicRels)*24 == len(l.rela.data), "dynamic relocation count mismatch")
	relatives := uint64(0)
	for i, r := range l.dynamicRels {
		p := l.rela.data[i*24:]
		le.PutUint64(p, r.off)
		info := uint64(r.typ)
		if r.sym != nil {
			info |= uint64(r.sym.dynIndex) << 32
		}
		le.PutUint64(p[8:], info)
		le.PutUint64(p[16:], uint64(r.add))
		if r.typ == elf.R_AARCH64_RELATIVE {
			relatives++
		}
	}
	l.finishEH()
	dyn := [][2]uint64{}
	add := func(t elf.DynTag, v uint64) { dyn = append(dyn, [2]uint64{uint64(t), v}) }
	for _, name := range l.libs {
		add(elf.DT_NEEDED, uint64(l.strAdd(name)))
	}
	if l.soname != "" {
		add(elf.DT_SONAME, uint64(l.strAdd(l.soname)))
	}
	add(elf.DT_STRTAB, l.dynstr.addr)
	add(elf.DT_STRSZ, l.dynstr.size)
	add(elf.DT_SYMTAB, l.dynsym.addr)
	add(elf.DT_SYMENT, 24)
	add(elf.DT_GNU_HASH, l.hash.addr)
	add(elf.DT_RELA, l.rela.addr)
	add(elf.DT_RELASZ, l.rela.size)
	add(elf.DT_RELAENT, 24)
	add(elf.DT_RELACOUNT, relatives)
	add(elf.DT_PLTGOT, l.got.addr)
	add(elf.DT_FLAGS, l.dynamicFlags())
	flags1 := l.dynamicFlags1()
	if l.interp != nil {
		flags1 |= uint64(elf.DF_1_PIE)
	}
	add(elf.DT_FLAGS_1, flags1)
	for _, pair := range []struct {
		role      int
		tag, size elf.DynTag
	}{{initArray, elf.DT_INIT_ARRAY, elf.DT_INIT_ARRAYSZ}, {finiArray, elf.DT_FINI_ARRAY, elf.DT_FINI_ARRAYSZ}} {
		var start, end uint64
		for _, s := range l.sections {
			if s.role == pair.role {
				if start == 0 {
					start = s.addr
				}
				end = s.addr + s.size
			}
		}
		if end > start {
			add(pair.tag, start)
			add(pair.size, end-start)
		}
	}
	check((len(dyn)+1)*16 <= len(l.dynamic.data), "dynamic table overflow")
	for i, pair := range dyn {
		le.PutUint64(l.dynamic.data[i*16:], pair[0])
		le.PutUint64(l.dynamic.data[i*16+8:], pair[1])
	}
}
func (l *linker) emit() []byte {
	names := []byte{0}
	nameIndex := func(s string) uint32 {
		n := uint32(len(names))
		names = append(names, []byte(s)...)
		names = append(names, 0)
		return n
	}
	headers := []elf.Section64{{}}
	for _, s := range l.sections {
		headers = append(headers, elf.Section64{Name: nameIndex(s.name), Type: uint32(s.typ), Flags: uint64(s.flags), Addr: s.addr, Off: s.addr, Size: s.size, Link: s.link, Info: s.info, Addralign: s.align, Entsize: s.entsize})
	}
	strindex := len(headers)
	headers = append(headers, elf.Section64{Name: nameIndex(".shstrtab"), Type: uint32(elf.SHT_STRTAB), Off: l.fileEnd, Size: uint64(len(names)), Addralign: 1})
	shoff := align(l.fileEnd+uint64(len(names)), 8)
	out := make([]byte, shoff+uint64(len(headers))*64)
	for _, s := range l.sections {
		if s.typ != elf.SHT_NOBITS {
			copy(out[s.addr:s.addr+s.size], s.data)
		}
	}
	copy(out[l.fileEnd:], names)
	ph := []elf.Prog64{{Type: uint32(elf.PT_PHDR), Flags: uint32(elf.PF_R), Off: 64, Vaddr: 64, Paddr: 64, Filesz: uint64(l.phnum * 56), Memsz: uint64(l.phnum * 56), Align: 8}, {Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R), Filesz: l.roEnd, Memsz: l.roEnd, Align: page}, {Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X), Off: l.textStart, Vaddr: l.textStart, Paddr: l.textStart, Filesz: l.textEnd - l.textStart, Memsz: l.textEnd - l.textStart, Align: page}, {Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_W), Off: l.rwStart, Vaddr: l.rwStart, Paddr: l.rwStart, Filesz: l.fileEnd - l.rwStart, Memsz: l.memEnd - l.rwStart, Align: page}, {Type: uint32(elf.PT_DYNAMIC), Flags: uint32(elf.PF_R | elf.PF_W), Off: l.dynamic.addr, Vaddr: l.dynamic.addr, Paddr: l.dynamic.addr, Filesz: l.dynamic.size, Memsz: l.dynamic.size, Align: 8}, {Type: uint32(elf.PT_GNU_RELRO), Flags: uint32(elf.PF_R), Off: l.rwStart, Vaddr: l.rwStart, Paddr: l.rwStart, Filesz: l.relroEnd - l.rwStart, Memsz: l.relroEnd - l.rwStart, Align: 1}, {Type: uint32(elf.PT_GNU_STACK), Flags: uint32(elf.PF_R | elf.PF_W), Align: 16}, {Type: uint32(elf.PT_GNU_EH_FRAME), Flags: uint32(elf.PF_R), Off: l.ehhdr.addr, Vaddr: l.ehhdr.addr, Paddr: l.ehhdr.addr, Filesz: l.ehhdr.size, Memsz: l.ehhdr.size, Align: 4}}
	for _, s := range l.sections {
		if s.typ == elf.SHT_NOTE {
			ph = append(ph, elf.Prog64{Type: uint32(elf.PT_NOTE), Flags: uint32(elf.PF_R), Off: s.addr, Vaddr: s.addr, Paddr: s.addr, Filesz: s.size, Memsz: s.size, Align: 4})
		}
	}
	if l.interp != nil {
		s := l.interp
		ph = append([]elf.Prog64{ph[0], {Type: uint32(elf.PT_INTERP), Flags: uint32(elf.PF_R), Off: s.addr, Vaddr: s.addr, Paddr: s.addr, Filesz: s.size, Memsz: s.size, Align: 1}}, ph[1:]...)
	}
	check(len(ph) == l.phnum, "program header count")
	header := elf.Header64{Ident: [16]byte{0x7f, 'E', 'L', 'F', 2, 1, 1}, Type: uint16(elf.ET_DYN), Machine: uint16(elf.EM_AARCH64), Version: 1, Phoff: 64, Shoff: shoff, Ehsize: 64, Phentsize: 56, Phnum: uint16(len(ph)), Shentsize: 64, Shnum: uint16(len(headers)), Shstrndx: uint16(strindex)}
	if l.entryName != "" {
		s := l.globals[l.entryName]
		check(s != nil, "missing entry %s", l.entryName)
		header.Entry = s.value()
	}
	var buf bytes.Buffer
	binary.Write(&buf, le, header)
	binary.Write(&buf, le, ph)
	copy(out, buf.Bytes())
	buf.Reset()
	binary.Write(&buf, le, headers)
	copy(out[shoff:], buf.Bytes())
	return out
}
