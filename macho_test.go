package golink

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 在 Go 内构造含导入分支和两种指针的 ARM64 对象，无需 Xcode 或桌面。
func machoFixture() []byte {
	const commands = 72 + 2*80 + 24 + 24
	const textOffset = 32 + commands
	const dataOffset = textOffset + 16
	const relocText = dataOffset + 16
	const relocData = relocText + 8
	const symOffset = relocData + 16
	str := []byte("\x00_main\x00_puts\x00_ptr\x00")
	b := make([]byte, symOffset+3*16+len(str))
	copy(b, mWords(0xfeedfacf, 0x100000c, 0, 1, 3, commands, 0, 0))
	s := b[32:]
	le.PutUint32(s, 0x19)
	le.PutUint32(s[4:], 72+2*80)
	le.PutUint64(s[32:], 32)
	le.PutUint64(s[40:], textOffset)
	le.PutUint64(s[48:], 32)
	le.PutUint32(s[64:], 2)
	section := func(i int, seg, name string, addr, size uint64, off, flags, reloc, count uint32) {
		p := s[72+i*80:]
		mName(p[:16], name)
		mName(p[16:32], seg)
		le.PutUint64(p[32:], addr)
		le.PutUint64(p[40:], size)
		le.PutUint32(p[48:], off)
		le.PutUint32(p[52:], 2)
		le.PutUint32(p[56:], reloc)
		le.PutUint32(p[60:], count)
		le.PutUint32(p[64:], flags)
	}
	section(0, "__TEXT", "__text", 0, 12, textOffset, 0x80000400, relocText, 1)
	section(1, "__DATA", "__data", 16, 16, dataOffset, 0, relocData, 2)
	copy(b[32+72+160:], mWords(2, 24, symOffset, 3, symOffset+48, uint32(len(str))))
	copy(b[32+72+160+24:], mWords(0x32, 24, 7, 15<<16, 26<<16|2<<8, 0))
	copy(b[textOffset:], mWords(0x52800000, 0x94000000, 0xd65f03c0))
	reloc := func(off int, addr, sym, kind, length uint32, pc bool) {
		le.PutUint32(b[off:], addr)
		v := sym | length<<25 | 1<<27 | kind<<28
		if pc {
			v |= 1 << 24
		}
		le.PutUint32(b[off+4:], v)
	}
	reloc(relocText, 4, 1, 2, 2, true)
	reloc(relocData, 0, 0, 0, 3, false)
	reloc(relocData+8, 8, 1, 0, 3, false)
	symbol := func(i int, name uint32, typ, sec byte, value uint64) {
		p := b[symOffset+i*16:]
		le.PutUint32(p, name)
		p[4] = typ
		p[5] = sec
		le.PutUint64(p[8:], value)
	}
	symbol(0, 1, 15, 1, 0)
	symbol(1, 7, 1, 0, 0)
	symbol(2, 13, 15, 2, 16)
	copy(b[symOffset+48:], str)
	return b
}

func iosFixtureRequest(t *testing.T) Request {
	t.Helper()
	root := t.TempDir()
	object := filepath.Join(root, "main.o")
	library := filepath.Join(root, "System.tbd")
	if err := os.WriteFile(object, machoFixture(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(library, []byte("--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-ios-simulator ]\ninstall-name: '/usr/lib/libSystem.B.dylib'\nexports:\n  - targets: [ arm64-ios-simulator ]\n    symbols: [ _puts ]\n...\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return Request{Format: 1, Target: "ios/arm64", Objects: []string{object}, Libraries: []string{library}, Output: filepath.Join(root, "Fixture"), IOS: &IOSOptions{Variant: "simulator", MinimumVersion: "15.0", SDKVersion: "26.2"}}
}

func TestMachOLink(t *testing.T) {
	r := iosFixtureRequest(t)
	if err := Link(r); err != nil {
		t.Fatal(err)
	}
	f, err := macho.Open(r.Output)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Type != macho.TypeExec || f.Cpu != macho.CpuArm64 || f.Flags&0x200000 == 0 {
		t.Fatal("Mach-O 类型或 PIE 不正确")
	}
	code, err := f.Section("__text").Data()
	if err != nil {
		t.Fatal(err)
	}
	if le.Uint32(code[4:]) != 0x94000002 {
		t.Fatalf("BL 没有正确指向 stub: %x", code)
	}
	data, _ := f.Section("__data").Data()
	if le.Uint64(data) != f.Section("__text").Addr {
		t.Fatal("指针没有指向 _main")
	}
	for _, l := range f.Loads {
		if s, ok := l.(*macho.Segment); ok {
			if s.Prot&6 == 6 {
				t.Fatal("存在可写可执行段")
			}
			if s.Name == "__DATA_CONST" && (s.Flag&0x10 == 0 || s.Offset%16384 != 0) {
				t.Fatal("只读重定位段不正确")
			}
		}
	}
	image, err := os.ReadFile(r.Output)
	if err != nil {
		t.Fatal(err)
	}
	seenBind, seenRebase := false, false
	for _, l := range f.Loads {
		raw := l.Raw()
		switch le.Uint32(raw) {
		case 0x32:
			if le.Uint32(raw[8:]) != 7 || le.Uint32(raw[12:]) != 15<<16 {
				t.Fatal("模拟器平台信息错误")
			}
		case 0x80000028:
			if le.Uint64(raw[8:]) != f.Section("__text").Addr-machoBase {
				t.Fatal("LC_MAIN 入口错误")
			}
		case 0x80000022:
			rebaseOff, rebaseLen := le.Uint32(raw[8:]), le.Uint32(raw[12:])
			bindOff, bindLen := le.Uint32(raw[16:]), le.Uint32(raw[20:])
			seenRebase = bytes.Contains(image[rebaseOff:rebaseOff+rebaseLen], []byte{0x23, 0, 0x51})
			seenBind = bytes.Count(image[bindOff:bindOff+bindLen], []byte("_puts\x00")) == 2
		case 0x1d:
			off, size := le.Uint32(raw[8:]), le.Uint32(raw[12:])
			sig := image[off : off+size]
			be := binary.BigEndian
			if be.Uint32(sig) != 0xfade0cc0 {
				t.Fatal("缺少 SuperBlob")
			}
			cd := sig[be.Uint32(sig[16:]):]
			count := be.Uint32(cd[28:])
			hashOffset := be.Uint32(cd[16:])
			if be.Uint32(cd[32:]) != off || count != (off+4095)/4096 {
				t.Fatal("签名覆盖范围错误")
			}
			for i := uint32(0); i < count; i++ {
				end := min((i+1)*4096, off)
				want := sha256.Sum256(image[i*4096 : end])
				if !bytes.Equal(cd[hashOffset+i*32:hashOffset+(i+1)*32], want[:]) {
					t.Fatal("代码页哈希不匹配")
				}
			}
		}
	}
	if !seenBind || !seenRebase {
		t.Fatalf("dyld 绑定/重定位缺失: %v/%v", seenBind, seenRebase)
	}
	first := append([]byte(nil), image...)
	if err = Link(r); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(r.Output)
	if !bytes.Equal(first, second) {
		t.Fatal("输出不确定")
	}
}

func TestMachOReject(t *testing.T) {
	for _, name := range []string{"平台", "部署版本", "CPU子类型", "重定位类型", "重定位越界", "缺失导出"} {
		t.Run(name, func(t *testing.T) {
			r := iosFixtureRequest(t)
			b := machoFixture()
			want := ""
			switch name {
			case "平台":
				r.IOS.Variant = "device"
				want = "TBD does not support"
			case "部署版本":
				r.IOS.MinimumVersion = "14.0"
				want = "newer deployment"
			case "CPU子类型":
				le.PutUint32(b[8:], 2)
				want = "CPU subtype"
			case "重定位类型":
				le.PutUint32(b[344+4:], uint32(11)<<28|3<<25|1<<27)
				want = "unsupported Mach-O relocation"
			case "重定位越界":
				le.PutUint32(b[344:], 1000)
				want = "outside section"
			case "缺失导出":
				copy(b[len(b)-10:], []byte("_none"))
				want = "unresolved Mach-O"
			}
			if err := os.WriteFile(r.Objects[0], b, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(r.Output, []byte("保留"), 0600); err != nil {
				t.Fatal(err)
			}
			err := Link(r)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("预期 %s，实际 %v", want, err)
			}
			got, _ := os.ReadFile(r.Output)
			if string(got) != "保留" {
				t.Fatal("失败破坏原产物")
			}
		})
	}
}
