package golink

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTBDReexportsAndTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Library.tbd")
	text := `--- !tapi-tbd
tbd-version: 4
targets: [ arm64-ios-simulator ]
install-name: '/Framework'
reexported-libraries:
  - targets: [ arm64-ios-simulator ]
    libraries: [ '/Private' ]
--- !tapi-tbd
tbd-version: 4
targets: [ arm64-ios-simulator ]
install-name: '/Private'
exports:
  - targets: [ arm64-ios-simulator ]
    symbols: [ '_puts', 'quoted]symbol', 'a''b' ]
    objc-classes: [ Example ]
  - targets: [ arm64-ios ]
    symbols: [ _device_only ]
...
`
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	lib := readTBD(path, "arm64-ios-simulator")
	for _, n := range []string{"_puts", "quoted]symbol", "a'b", "_OBJC_CLASS_$_Example", "_OBJC_METACLASS_$_Example"} {
		if !lib.symbols[n] {
			t.Fatalf("没有导出 %s", n)
		}
	}
	if lib.symbols["_device_only"] {
		t.Fatal("混入其他目标导出")
	}
	if !tbdTarget("/usr/lib/system/libsystem_kernel.dylib", []string{"arm64-macos"}, "arm64-ios-simulator") || tbdTarget("/Other", []string{"arm64-macos"}, "arm64-ios-simulator") || tbdTarget("/usr/lib/system/libsystem_kernel.dylib", []string{"arm64-macos"}, "arm64-ios") {
		t.Fatal("SDK兼容范围不正确")
	}
}
