package golink

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type member struct {
	name string
	data []byte
	defs []string
	used bool
}

func readNativeArchive(p string) []*member {
	var members []*member
	b, err := os.ReadFile(p)
	check(err == nil && bytes.HasPrefix(b, []byte("!<arch>\n")), "native archive %s", p)
	var longNames []byte
	pos := 8
	for pos+60 <= len(b) {
		h := b[pos : pos+60]
		size, err := strconv.Atoi(strings.TrimSpace(string(h[48:58])))
		check(err == nil && size >= 0 && size <= len(b)-pos-60 && string(h[58:60]) == "`\n", "archive member bounds")
		data := b[pos+60 : pos+60+size]
		name := strings.TrimSpace(string(h[:16]))
		if strings.HasPrefix(name, "#1/") {
			n, e := strconv.Atoi(name[3:])
			check(e == nil && n >= 0 && n <= len(data), "BSD archive name")
			name = string(data[:n])
			data = data[n:]
		}
		pos += 60 + size + size%2
		if name == "//" {
			longNames = data
			continue
		}
		if name == "/" || name == "/SYM64/" || strings.HasPrefix(name, "__.SYMDEF") {
			continue
		}
		if strings.HasPrefix(name, "/") {
			offset, err := strconv.Atoi(name[1:])
			check(err == nil && offset >= 0 && offset < len(longNames), "GNU archive name")
			end := bytes.IndexByte(longNames[offset:], '\n')
			check(end >= 0, "unterminated GNU archive name")
			name = strings.TrimSuffix(string(longNames[offset:offset+end]), "/")
		}
		members = append(members, &member{name: fmt.Sprintf("%s(%s)", p, name), data: data})
	}
	check(pos == len(b), "truncated native archive %s", p)
	return members
}

func (l *linker) loadArchives(paths []string) {
	var members []*member
	for _, p := range paths {
		for _, m := range readNativeArchive(p) {
			check(bytes.HasPrefix(m.data, []byte("\x7fELF")), "unsupported native archive member %s", m.name)
			f, e := elf.NewFile(bytes.NewReader(m.data))
			check(e == nil, "archive ELF %s", m.name)
			check(f.Type == elf.ET_REL && f.Machine == elf.EM_AARCH64, "unsupported archive object %s", m.name)
			syms, e := f.Symbols()
			check(e == nil, "archive symbols")
			for _, s := range syms {
				if s.Section != elf.SHN_UNDEF && elf.ST_BIND(s.Info) != elf.STB_LOCAL {
					m.defs = append(m.defs, s.Name)
				}
			}
			f.Close()
			members = append(members, m)
		}
	}
	for {
		changed := false
		for _, m := range members {
			if m.used {
				continue
			}
			needed := false
			for _, name := range m.defs {
				s := l.globals[name]
				if s != nil && s.Section == elf.SHN_UNDEF && !l.libSymbols[name] && elf.ST_BIND(s.Info) != elf.STB_WEAK {
					needed = true
					break
				}
			}
			if needed {
				l.load(m.name, m.data)
				m.used = true
				l.loadedArchives++
				changed = true
			}
		}
		if !changed {
			break
		}
	}
}
func (l *linker) countFDE() int {
	count := 0
	for _, s := range l.sections {
		if !strings.HasPrefix(s.name, ".eh_frame.") {
			continue
		}
		for p := 0; p+4 <= len(s.data); {
			n := int(le.Uint32(s.data[p:]))
			if n == 0 {
				p += 4
				continue
			}
			check(n != int(^uint32(0)) && p+4+n <= len(s.data) && n >= 4, "unsupported EH frame length")
			if le.Uint32(s.data[p+4:]) != 0 {
				count++
			}
			p += 4 + n
		}
	}
	return count
}
func uleb(b []byte, p *int) uint64 {
	var v uint64
	for shift := uint(0); ; shift += 7 {
		check(*p < len(b) && shift < 64, "bad LEB")
		x := b[*p]
		*p++
		v |= uint64(x&127) << shift
		if x < 128 {
			return v
		}
	}
}
func (l *linker) finishEH() {
	type entry struct{ pc, addr uint64 }
	var entries []entry
	var start uint64
	for _, s := range l.sections {
		if !strings.HasPrefix(s.name, ".eh_frame.") {
			continue
		}
		if start == 0 {
			start = s.addr
		}
		cies := map[int]byte{}
		for p := 0; p+4 <= len(s.data); {
			n := int(le.Uint32(s.data[p:]))
			if n == 0 {
				p += 4
				continue
			}
			id := le.Uint32(s.data[p+4:])
			end := p + 4 + n
			if id == 0 {
				q := p + 8
				check(q < end, "truncated CIE")
				version := s.data[q]
				q++
				check(version == 1 || version == 3, "unsupported CIE version")
				a := q
				for q < end && s.data[q] != 0 {
					q++
				}
				check(q < end, "CIE augmentation")
				aug := string(s.data[a:q])
				q++
				uleb(s.data[:end], &q)
				uleb(s.data[:end], &q)
				if version == 1 {
					check(q < end, "truncated CIE register")
					q++
				} else {
					uleb(s.data[:end], &q)
				}
				encoding := byte(0)
				if strings.HasPrefix(aug, "z") {
					length := uleb(s.data[:end], &q)
					check(length <= uint64(end-q), "CIE augmentation length")
					augEnd := q + int(length)
					for _, c := range aug[1:] {
						switch c {
						case 'R':
							check(q < augEnd, "truncated CIE encoding")
							encoding = s.data[q]
							q++
						case 'L':
							check(q < augEnd, "truncated CIE LSDA")
							q++
						case 'S':
						default:
							check(false, "unsupported CIE augmentation %q", aug)
						}
					}
					check(q <= augEnd, "CIE augmentation bounds")
				}
				check(encoding == 0x1b, "unsupported FDE encoding %#x", encoding)
				cies[p] = encoding
			} else {
				check(n >= 12, "truncated FDE")
				cie := p + 4 - int(id)
				_, ok := cies[cie]
				check(ok, "FDE references unknown CIE")
				pc := uint64(int64(s.addr+uint64(p+8)) + int64(int32(le.Uint32(s.data[p+8:]))))
				entries = append(entries, entry{pc, s.addr + uint64(p)})
			}
			p = end
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].pc < entries[j].pc })
	check(12+8*len(entries) == len(l.ehhdr.data), "EH count mismatch")
	h := l.ehhdr.data
	copy(h, []byte{1, 0x1b, 3, 0x3b})
	if start == 0 {
		start = l.ehhdr.addr + 4
	}
	le.PutUint32(h[4:], signed32(int64(start)-int64(l.ehhdr.addr+4)))
	le.PutUint32(h[8:], uint32(len(entries)))
	for i, e := range entries {
		le.PutUint32(h[12+8*i:], signed32(int64(e.pc)-int64(l.ehhdr.addr)))
		le.PutUint32(h[16+8*i:], signed32(int64(e.addr)-int64(l.ehhdr.addr)))
	}
}
