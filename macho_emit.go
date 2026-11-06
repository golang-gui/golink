package golink

import (
	"bytes"
	"crypto/sha256"
	"path/filepath"
	"sort"

	"github.com/golang-gui/golink/internal/codesign"
)

func appendULEB(b []byte, v uint64) []byte {
	for {
		c := byte(v & 127)
		v >>= 7
		if v != 0 {
			c |= 128
		}
		b = append(b, c)
		if v == 0 {
			return b
		}
	}
}
func appendSLEB(b []byte, v int64) []byte {
	for {
		c := byte(v & 127)
		v >>= 7
		done := v == 0 && c&64 == 0 || v == -1 && c&64 != 0
		if !done {
			c |= 128
		}
		b = append(b, c)
		if done {
			return b
		}
	}
}

func (l *mLinker) dyldFixups() ([]byte, []byte) {
	sort.SliceStable(l.fixups, func(i, j int) bool {
		a, b := l.fixups[i], l.fixups[j]
		if a.section.segIndex != b.section.segIndex {
			return a.section.segIndex < b.section.segIndex
		}
		return a.section.addr+a.off < b.section.addr+b.off
	})
	rebase := []byte{0x11}
	bind := []byte{0x51}
	segmentStart := func(s *mSection) uint64 {
		switch s.seg {
		case "__DATA_CONST":
			return machoBase + l.constStart
		case "__DATA":
			return machoBase + l.dataStart
		}
		check(false, "fixup in unsupported segment %s", s.seg)
		return 0
	}
	for _, f := range l.fixups {
		address := f.section.addr + f.off - segmentStart(f.section)
		if f.symbol == nil {
			rebase = append(rebase, byte(0x20|f.section.segIndex))
			rebase = appendULEB(rebase, address)
			rebase = append(rebase, 0x51)
		} else {
			s := f.symbol
			if s.ordinal < 16 {
				bind = append(bind, byte(0x10|s.ordinal))
			} else {
				bind = append(bind, 0x20)
				bind = appendULEB(bind, uint64(s.ordinal))
			}
			flags := byte(0)
			if s.Desc&0x40 != 0 {
				flags = 1
			}
			bind = append(bind, 0x40|flags)
			bind = append(bind, []byte(s.Name)...)
			bind = append(bind, 0)
			bind = append(bind, 0x60)
			bind = appendSLEB(bind, f.add)
			bind = append(bind, byte(0x70|f.section.segIndex))
			bind = appendULEB(bind, address)
			bind = append(bind, 0x90)
		}
	}
	return append(rebase, 0), append(bind, 0)
}

type exportNode struct {
	symbol   *mSymbol
	children map[byte]*exportNode
	offset   int
}

func (l *mLinker) exportTrie() []byte {
	root := &exportNode{children: map[byte]*exportNode{}}
	for _, s := range l.exports {
		n := root
		for i := 0; i < len(s.Name); i++ {
			if n.children[s.Name[i]] == nil {
				n.children[s.Name[i]] = &exportNode{children: map[byte]*exportNode{}}
			}
			n = n.children[s.Name[i]]
		}
		n.symbol = s
	}
	var nodes []*exportNode
	keys := func(n *exportNode) []int {
		k := []int{}
		for c := range n.children {
			k = append(k, int(c))
		}
		sort.Ints(k)
		return k
	}
	var visit func(*exportNode)
	visit = func(n *exportNode) {
		nodes = append(nodes, n)
		for _, c := range keys(n) {
			visit(n.children[byte(c)])
		}
	}
	visit(root)
	encode := func(n *exportNode) []byte {
		var terminal []byte
		if n.symbol != nil {
			flags := uint64(0)
			if n.symbol.Desc&0x80 != 0 {
				flags = 4
			}
			terminal = appendULEB(terminal, flags)
			terminal = appendULEB(terminal, n.symbol.value()-machoBase)
		}
		b := appendULEB(nil, uint64(len(terminal)))
		b = append(b, terminal...)
		check(len(n.children) < 256, "export trie fanout")
		b = append(b, byte(len(n.children)))
		for _, c := range keys(n) {
			b = append(b, byte(c), 0)
			b = appendULEB(b, uint64(n.children[byte(c)].offset))
		}
		return b
	}
	for pass := 0; pass < 20; pass++ {
		cursor := 0
		changed := false
		for _, n := range nodes {
			if n.offset != cursor {
				n.offset = cursor
				changed = true
			}
			cursor += len(encode(n))
		}
		if !changed {
			var b []byte
			for _, n := range nodes {
				b = append(b, encode(n)...)
			}
			return b
		}
	}
	check(false, "export trie layout did not converge")
	return nil
}

func (l *mLinker) segmentCommand(name string, addr, memsize, offset, filesize uint64, prot, flags uint32) []byte {
	var sections []*mSection
	for _, s := range l.sections {
		if s.seg == name {
			sections = append(sections, s)
		}
	}
	b := make([]byte, 72+80*len(sections))
	le.PutUint32(b, 0x19)
	le.PutUint32(b[4:], uint32(len(b)))
	mName(b[8:24], name)
	le.PutUint64(b[24:], addr)
	le.PutUint64(b[32:], memsize)
	le.PutUint64(b[40:], offset)
	le.PutUint64(b[48:], filesize)
	le.PutUint32(b[56:], prot)
	le.PutUint32(b[60:], prot)
	le.PutUint32(b[64:], uint32(len(sections)))
	le.PutUint32(b[68:], flags)
	for i, s := range sections {
		p := b[72+i*80:]
		mName(p[:16], s.name)
		mName(p[16:32], s.seg)
		le.PutUint64(p[32:], s.addr)
		le.PutUint64(p[40:], s.size)
		if s.flags&255 != 1 {
			le.PutUint32(p[48:], uint32(s.off))
		}
		power := uint32(0)
		for uint64(1)<<power < s.alignment {
			power++
		}
		le.PutUint32(p[52:], power)
		le.PutUint32(p[64:], s.flags)
		le.PutUint32(p[68:], s.reserved1)
		le.PutUint32(p[72:], s.reserved2)
	}
	return b
}

func (l *mLinker) emitMachO() []byte {
	rebases, binds := l.dyldFixups()
	exports := l.exportTrie()
	var tail []byte
	appendBlob := func(b []byte) (uint32, uint32) {
		for len(tail)%8 != 0 {
			tail = append(tail, 0)
		}
		off := uint32(l.linkedit) + uint32(len(tail))
		tail = append(tail, b...)
		return off, uint32(len(b))
	}
	rebaseOff, rebaseSize := appendBlob(rebases)
	bindOff, bindSize := appendBlob(binds)
	exportOff, exportSize := appendBlob(exports)
	str := []byte{0}
	var symbols []byte
	indexes := map[*mSymbol]uint32{}
	all := append(append([]*mSymbol{}, l.exports...), l.imports...)
	for i, s := range all {
		indexes[s] = uint32(i)
		p := make([]byte, 16)
		le.PutUint32(p, uint32(len(str)))
		str = append(str, []byte(s.Name)...)
		str = append(str, 0)
		p[4] = 1
		desc := s.Desc
		if !s.imported {
			p[4] = 0xf
			p[5] = byte(s.part.out.index)
			le.PutUint64(p[8:], s.value())
		} else {
			desc = desc&0xff | uint16(s.ordinal)<<8
		}
		le.PutUint16(p[6:], desc)
		symbols = append(symbols, p...)
	}
	symoff, _ := appendBlob(symbols)
	stroff, strsize := appendBlob(str)
	var indirect []byte
	for _, s := range l.stubSymbols {
		indirect = append(indirect, mWords(indexes[s])...)
	}
	l.got.reserved1 = uint32(len(l.stubSymbols))
	for _, s := range l.gotSymbols {
		index := uint32(0x80000000)
		if s.imported {
			index = indexes[s]
		} else if s.absolute {
			index |= 0x40000000
		}
		indirect = append(indirect, mWords(index)...)
	}
	indirectOff, _ := appendBlob(indirect)
	codeSize := align(l.linkedit+uint64(len(tail)), 16)
	id := filepath.Base(l.r.Output)
	signSize := uint64(codesign.Size(int64(codeSize), id))
	end := codeSize + signSize
	check(end < 1<<30, "Mach-O output too large")
	commands := [][]byte{
		l.segmentCommand("__PAGEZERO", 0, machoBase, 0, 0, 0, 0),
		l.segmentCommand("__TEXT", machoBase, l.textEnd, 0, l.textEnd, 5, 0),
		l.segmentCommand("__DATA_CONST", machoBase+l.constStart, l.constEnd-l.constStart, l.constStart, l.constEnd-l.constStart, 3, 0x10),
		l.segmentCommand("__DATA", machoBase+l.dataStart, l.dataEnd-l.dataStart, l.dataStart, l.dataFileEnd-l.dataStart, 3, 0),
		l.segmentCommand("__LINKEDIT", machoBase+l.linkedit, align(end-l.linkedit, page), l.linkedit, end-l.linkedit, 1, 0),
		mWords(0x80000022, 48, rebaseOff, rebaseSize, bindOff, bindSize, 0, 0, 0, 0, exportOff, exportSize),
		mWords(2, 24, symoff, uint32(len(all)), stroff, strsize),
		mWords(0xb, 80, 0, 0, 0, uint32(len(l.exports)), uint32(len(l.exports)), uint32(len(l.imports)), 0, 0, 0, 0, 0, 0, indirectOff, uint32(len(indirect)/4), 0, 0, 0, 0),
		mStringCommand(0xe, "/usr/lib/dyld", 12),
	}
	minimum, e := machoVersion(l.r.IOS.MinimumVersion)
	check(e == nil, "minimum version: %v", e)
	sdk, e := machoVersion(l.r.IOS.SDKVersion)
	check(e == nil, "SDK version: %v", e)
	platform := uint32(2)
	if l.r.IOS.Variant == "simulator" {
		platform = 7
	}
	commands = append(commands, mWords(0x32, 24, platform, minimum, sdk, 0))
	for _, lib := range l.libraries {
		b := mStringCommand(0xc, lib.name, 24)
		le.PutUint32(b[16:], lib.current)
		le.PutUint32(b[20:], lib.compat)
		commands = append(commands, b)
	}
	entry := l.r.Entry
	if entry == "" {
		entry = "_main"
	}
	s := l.globals[entry]
	check(s != nil && !s.imported && s.part != nil && s.part.out.seg == "__TEXT", "invalid Mach-O entry %s", entry)
	off := s.value() - machoBase
	commands = append(commands, mWords(0x80000028, 24, uint32(off), uint32(off>>32), 0, 0))
	commands = append(commands, mWords(0x1d, 16, uint32(codeSize), uint32(signSize)))
	hash := sha256.New()
	hash.Write([]byte(l.r.IOS.Variant + "/" + l.r.IOS.MinimumVersion + "/" + l.r.IOS.SDKVersion))
	for _, section := range l.sections {
		hash.Write(section.data)
	}
	uuid := make([]byte, 24)
	le.PutUint32(uuid, 0x1b)
	le.PutUint32(uuid[4:], 24)
	copy(uuid[8:], hash.Sum(nil)[:16])
	commands = append(commands, uuid)
	commandSize := 0
	for _, c := range commands {
		commandSize += len(c)
	}
	check(32+commandSize <= 16384, "Mach-O load commands exceed reserved header")
	out := make([]byte, end)
	for _, s := range l.sections {
		if s.flags&255 != 1 {
			check(uint64(len(s.data)) == s.size, "Mach-O section data size %s", s.name)
			copy(out[s.off:], s.data)
		}
	}
	copy(out[l.linkedit:], tail)
	copy(out, mWords(0xfeedfacf, 0x100000c, 0, 2, uint32(len(commands)), uint32(commandSize), 0x200085, 0))
	p := 32
	for _, c := range commands {
		copy(out[p:], c)
		p += len(c)
	}
	codesign.Sign(out[codeSize:], bytes.NewReader(out[:codeSize]), id, int64(codeSize), 0, int64(l.textEnd), true)
	return out
}
