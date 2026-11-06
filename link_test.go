package golink

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 用 Go 写原生 ELF fixture，测试运行不需要 NDK、桌面或原生编译器。
func objectFixture() []byte {
	names := []byte("\x00.text\x00.data\x00.rela.data\x00.symtab\x00.strtab\x00.shstrtab\x00")
	name := func(s string) uint32 { return uint32(bytes.Index(names, []byte(s+"\x00"))) }
	sections := []elf.Section64{{},
		{Name: name(".text"), Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), Off: 64, Size: 4, Addralign: 4},
		{Name: name(".data"), Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_WRITE), Off: 72, Size: 8, Addralign: 8},
		{Name: name(".rela.data"), Type: uint32(elf.SHT_RELA), Off: 80, Size: 24, Link: 4, Info: 2, Addralign: 8, Entsize: 24},
		{Name: name(".symtab"), Type: uint32(elf.SHT_SYMTAB), Off: 104, Size: 72, Link: 5, Info: 1, Addralign: 8, Entsize: 24},
		{Name: name(".strtab"), Type: uint32(elf.SHT_STRTAB), Off: 176, Size: 13, Addralign: 1},
		{Name: name(".shstrtab"), Type: uint32(elf.SHT_STRTAB), Off: 192, Size: uint64(len(names)), Addralign: 1},
	}
	const shoff = 256
	b := make([]byte, shoff+64*len(sections))
	le.PutUint32(b[64:], 0xd65f03c0) // ARM64 RET。
	le.PutUint64(b[88:], uint64(1)<<32|uint64(elf.R_AARCH64_ABS64))
	le.PutUint32(b[128:], 1)
	b[132] = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC)
	le.PutUint16(b[134:], 1)
	le.PutUint64(b[144:], 4)
	le.PutUint32(b[152:], 7)
	b[156] = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_OBJECT)
	le.PutUint16(b[158:], 2)
	le.PutUint64(b[168:], 8)
	copy(b[176:], "\x00entry\x00value\x00")
	copy(b[192:], names)
	h := elf.Header64{Ident: [16]byte{0x7f, 'E', 'L', 'F', 2, 1, 1}, Type: uint16(elf.ET_REL), Machine: uint16(elf.EM_AARCH64), Version: 1, Shoff: shoff, Ehsize: 64, Shentsize: 64, Shnum: uint16(len(sections)), Shstrndx: 6}
	var buf bytes.Buffer
	binary.Write(&buf, le, h)
	copy(b, buf.Bytes())
	buf.Reset()
	binary.Write(&buf, le, sections)
	copy(b[shoff:], buf.Bytes())
	return b
}

func fixtureRequest(t *testing.T, data []byte) Request {
	t.Helper()
	root := t.TempDir()
	object := filepath.Join(root, "中文 object.o")
	if err := os.WriteFile(object, data, 0600); err != nil {
		t.Fatal(err)
	}
	return Request{Format: 1, Target: "android/arm64", Output: filepath.Join(root, "library.so"), Objects: []string{object}}
}

func TestLink(t *testing.T) {
	r := fixtureRequest(t, objectFixture())
	r.SONAME, r.Symbolic, r.NoDelete = "libfixture.so", true, true
	if err := Link(r); err != nil {
		t.Fatal(err)
	}
	f, err := elf.Open(r.Output)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Type != elf.ET_DYN || f.Machine != elf.EM_AARCH64 {
		t.Fatal("输出类型不对")
	}
	loads, relro := 0, 0
	var relroEnd uint64
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_LOAD:
			loads++
			if p.Align != 16384 || p.Off%16384 != p.Vaddr%16384 || p.Flags&(elf.PF_W|elf.PF_X) == elf.PF_W|elf.PF_X || p.Memsz < p.Filesz {
				t.Fatal("LOAD 权限或对齐错误")
			}
		case elf.PT_GNU_RELRO:
			relro++
			relroEnd = p.Vaddr + p.Memsz
			if relroEnd%16384 != 0 {
				t.Fatal("RELRO 未对齐")
			}
		case elf.PT_GNU_STACK:
			if p.Flags&elf.PF_X != 0 {
				t.Fatal("栈可执行")
			}
		}
	}
	if loads != 3 || relro != 1 {
		t.Fatalf("段缺失: LOAD=%d RELRO=%d", loads, relro)
	}
	data, err := f.Section(".data.0").Data()
	if err != nil {
		t.Fatal(err)
	}
	if le.Uint64(data) != f.Section(".text.0").Addr || f.Section(".data.0").Addr < relroEnd {
		t.Fatal("ABS64 结果或可变数据位置错误")
	}
	rela, _ := f.Section(".rela.dyn").Data()
	if len(rela) != 24 || le.Uint64(rela) != f.Section(".data.0").Addr || le.Uint64(rela[8:]) != uint64(elf.R_AARCH64_RELATIVE) || le.Uint64(rela[16:]) != f.Section(".text.0").Addr {
		t.Fatalf("动态重定位错误: %x", rela)
	}
	soname, _ := f.DynString(elf.DT_SONAME)
	if len(soname) != 1 || soname[0] != r.SONAME {
		t.Fatalf("SONAME=%q", soname)
	}
	first, _ := os.ReadFile(r.Output)
	if err = Link(r); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(r.Output)
	if !bytes.Equal(first, second) {
		t.Fatal("相同输入必须产生确定结果")
	}
}

func TestRejectAndPreserveOutput(t *testing.T) {
	for _, name := range []string{"架构", "TLS", "重定位越界", "未知重定位", "未知段", "重复强符号", "损坏归档"} {
		t.Run(name, func(t *testing.T) {
			b := objectFixture()
			want := ""
			switch name {
			case "架构":
				le.PutUint16(b[18:], uint16(elf.EM_X86_64))
				want = "unsupported object"
			case "TLS":
				le.PutUint64(b[256+64+8:], uint64(elf.SHF_ALLOC|elf.SHF_TLS))
				want = "TLS sections"
			case "重定位越界":
				le.PutUint64(b[80:], 4)
				want = "relocation outside"
			case "未知重定位":
				le.PutUint64(b[88:], uint64(1)<<32|uint64(elf.R_AARCH64_TLSLE_ADD_TPREL_HI12))
				want = "unsupported relocation"
			case "未知段":
				le.PutUint32(b[256+64+4:], uint32(elf.SHT_DYNAMIC))
				want = "unsupported loadable section"
			case "重复强符号":
				want = "duplicate symbol"
			case "损坏归档":
				want = "native archive"
			}
			r := fixtureRequest(t, b)
			if name == "重复强符号" {
				r.Objects = append(r.Objects, r.Objects[0])
			}
			if name == "损坏归档" {
				r.Archives = []string{r.Objects[0]}
			}
			if err := os.WriteFile(r.Output, []byte("原有结果"), 0600); err != nil {
				t.Fatal(err)
			}
			err := Link(r)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("预期 %s，实际 %v", want, err)
			}
			got, _ := os.ReadFile(r.Output)
			if string(got) != "原有结果" {
				t.Fatal("失败覆盖了原产物")
			}
		})
	}
}

func TestRequest(t *testing.T) {
	for _, input := range []string{
		`{"format":2,"target":"android/arm64","output":"x","objects":["a.o"]}`,
		`{"format":1,"target":"ios/arm64","output":"x","objects":["a.o"]}`,
		`{"format":1,"target":"android/arm64","output":"x","objects":["a.o"],"lld":true}`,
		`{"format":1,"target":"android/arm64","output":"x","objects":["a.o"]} {}`,
	} {
		if _, err := ReadRequest(strings.NewReader(input)); err == nil {
			t.Fatalf("没有拒绝 %s", input)
		}
	}
}

// 记录取自 NDK libc.so 的 GNU hash chain，预期不是运行时重算。
func TestGNUHashReference(t *testing.T) {
	for name, want := range ndkHashReference {
		if got := gnuHash(name) &^ 1; got != want {
			t.Fatalf("%s: %#x != %#x", name, got, want)
		}
	}
}

func TestArchiveResolution(t *testing.T) {
	r := fixtureRequest(t, objectFixture())
	member := objectFixture()
	// 移除定义，使首个对象必须从归档获取 entry。
	b := objectFixture()
	le.PutUint16(b[134:], 0)
	if err := os.WriteFile(r.Objects[0], b, 0600); err != nil {
		t.Fatal(err)
	}
	// 归档只定义 entry，value 为局部符号。
	member[156] = byte(elf.STT_OBJECT)
	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")
	fmt.Fprintf(&archive, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", "member.o/", 0, 0, 0, "100644", len(member))
	archive.Write(member)
	if len(member)%2 != 0 {
		archive.WriteByte('\n')
	}
	p := filepath.Join(filepath.Dir(r.Output), "native.a")
	if err := os.WriteFile(p, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	r.Archives = []string{p}
	if err := Link(r); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("!<arch>\nx"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Link(r); err == nil || !strings.Contains(err.Error(), "truncated native archive") {
		t.Fatalf("不应忽略归档末尾残缺数据: %v", err)
	}
}

func TestWeakCommonAndBranch(t *testing.T) {
	t.Run("强定义替换弱定义", func(t *testing.T) {
		r := fixtureRequest(t, objectFixture())
		weak := objectFixture()
		weak[132] = byte(elf.STB_WEAK)<<4 | byte(elf.STT_FUNC)
		weak[156] = byte(elf.STT_OBJECT)
		p := filepath.Join(filepath.Dir(r.Output), "weak.o")
		if err := os.WriteFile(p, weak, 0600); err != nil {
			t.Fatal(err)
		}
		r.Objects = append([]string{p}, r.Objects...)
		if err := Link(r); err != nil {
			t.Fatal(err)
		}
		f, err := elf.Open(r.Output)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		syms, err := f.DynamicSymbols()
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range syms {
			if s.Name == "entry" && (s.Value != f.Section(".text.1").Addr || elf.ST_BIND(s.Info) != elf.STB_GLOBAL) {
				t.Fatal("弱定义没有被强定义替换")
			}
		}
	})
	t.Run("COMMON", func(t *testing.T) {
		b := objectFixture()
		le.PutUint16(b[158:], uint16(elf.SHN_COMMON))
		le.PutUint64(b[160:], 32)
		le.PutUint64(b[168:], 64)
		r := fixtureRequest(t, b)
		if err := Link(r); err != nil {
			t.Fatal(err)
		}
		f, err := elf.Open(r.Output)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		s := f.Section(".common.value")
		if s == nil || s.Type != elf.SHT_NOBITS || s.Size != 64 || s.Addralign != 32 || s.Addr%32 != 0 {
			t.Fatalf("COMMON 分配错误: %+v", s)
		}
	})
	t.Run("CALL26", func(t *testing.T) {
		b := objectFixture()
		le.PutUint32(b[64:], 0x94000000) // BL 的操作码；立即数字段初始为零。
		le.PutUint32(b[256+3*64+44:], 1)
		le.PutUint64(b[88:], uint64(2)<<32|uint64(elf.R_AARCH64_CALL26))
		r := fixtureRequest(t, b)
		if err := Link(r); err != nil {
			t.Fatal(err)
		}
		f, err := elf.Open(r.Output)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		code, _ := f.Section(".text.0").Data()
		// 当前 fixture 中代码位于 0x4000，可变数据位于 0xc000；BL +0x8000。
		if got := le.Uint32(code); got != 0x94002000 {
			t.Fatalf("BL 机器码: %#x", got)
		}
	})
}
