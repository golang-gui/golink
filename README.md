# golink

A small, independent native linker written in Go. It consumes native objects
emitted by the official Go linker and small precompiled native support objects.
It does not patch Go, compile C, discover an SDK, or implement UI policy.

The current implementation is experimental and supports **Android ARM64 ELF** and **iOS ARM64 Mach-O**
(device and simulator). It is not a general replacement for LLVM LLD or GNU ld.

## Build and use

```sh
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o golink ./cmd/golink
./golink --version
./golink -request request.json
```

Request format 1:

```json
{
  "format": 1,
  "target": "android/arm64",
  "output": "libapplication.so",
  "objects": ["go.o", "native-entry.o", "runtime-support.o"],
  "archives": ["builtins.a"],
  "libraries": ["target/libc.so", "target/libdl.so", "target/liblog.so"],
  "symbolic": true,
  "nodelete": true
}
```

All paths are resolved from the process working directory. `libraries` contains
explicit target ELF inputs or TBD v4 files; no host library search occurs.
`soname` is Android-only. `entry` defaults to `_main` on iOS; Android uses it
only for controlled native PIE probes, not general executable linking. The caller owns target input provenance, Go version and ABI matching.
Unknown request fields, targets, section features and relocations are errors.
Failed linking preserves the previous output. Output contains no DWARF sections,
including when the Go compiler generated debug input.

The Go API exposes `ReadRequest` and `Link`. All link state belongs to a single
invocation. The CLI request protocol is independent of GOUI and LLD syntax.

## iOS

The same Go API links iOS input without any native linker executable:

```json
{
  "format": 1,
  "target": "ios/arm64",
  "output": "Application",
  "objects": ["main.o", "platform-metadata.o"],
  "archives": ["go.a"],
  "libraries": ["SDK/usr/lib/libSystem.tbd", "SDK/Foundation.tbd"],
  "reexports": ["SDK/CoreFoundation.tbd"],
  "ios": {"variant": "simulator", "minimum_version": "15.0", "sdk_version": "26.2"}
}
```

`variant` is `device` or `simulator`. Archives are consumed in full, matching Go's
external-archive output. `reexports` supplies explicit dependency stubs without
adding root load commands; incomplete reexport closure is an error. Only the
TBD v4 scalar/mapping/flow-sequence subset used by the verified SDK is supported.
Three simulator host-library tags follow the narrow SDK compatibility exception
also documented by LLD 22.1.8; arbitrary cross-platform libraries are rejected.

Output is PIE with dyld rebasing/eager binding, exports, native section names,
module initializers, compact/DWARF unwind lookup and an ad-hoc Mach-O signature.
App bundle signing, entitlements, profiles and IPA packaging remain the caller's
responsibility. An ad-hoc executable signature does not authorize device install.
TLS imports, arm64e/authenticated pointers, personality/LSDA unwind data, branch
trampolines, LTO and general C++ linking are unsupported. Non-loadable DWARF is
omitted. SDK redistribution rights remain with the SDK provider.

## Scope

- ELF64 little-endian ARM64 ET_REL inputs; bounded native archives with ELF
  members, strong/weak/COMMON resolution and explicit shared library symbols.
- ABS64, PREL32, ADRP/ADD/LDST page relocations, GOT references and CALL/JUMP26.
- Relative and symbol dynamic relocations, GNU hash, eager binding, RELRO,
  non-executable stack, 16 KiB LOAD alignment, init/fini arrays and the restricted
  CFI encoding used by the tested Go/NDK inputs.
- Branch overflow is rejected. TLS, symbol versions, COMDAT groups, link-order
  sections, LTO, C++ and branch trampolines are not supported. Archive extraction
  resolves the request's controlled object set to a fixed point; it does not
  promise all GNU archive order/interposition behavior.
- Bounded inputs (512 MiB per loadable section, 1 GiB output) are intentional.
  This is a local build tool, not a sandbox for untrusted object uploads.

## Tests and evidence

```sh
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
```

Committed tests create ELF and archive fixtures with Go; they require no NDK or
mobile runtime. GNU hash constants were read from the NDK libc GNU hash table,
with the exact reference digest recorded in the test. Tests assert relocation
results, segment permissions, deterministic output and failure preservation.

The private integration fixture is not shipped in this module: official Go
1.25.8 GLES/standard-library app, 27 native objects and 192699 loadable
relocations. Android execution and cross-host output checks are recorded by the
consumer project; they do not imply arbitrary Go version, physical device support. iOS simulator runtime checks and unsigned device
builds are recorded separately in GOUI; they are not device runtime acceptance. Final publication requires source review and a stable release.

## References

The implementation reads native ELF structures through Go's `debug/elf`.
The ELF/Mach-O implementation was written independently; no Go toolchain fork
or LLD source is included. The small Go ad-hoc signature utility is reused under
its BSD license; see [third-party notices](THIRD_PARTY.md).
Applicable references:

- [AAELF64 ABI](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst)
- [Go 1.25.8 external-link driver](https://github.com/golang/go/blob/go1.25.8/src/cmd/link/internal/ld/lib.go)
- [Android Bionic ELF loader](https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/linker_phdr.cpp)

- [Apple Mach-O ARM64 relocations](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/arm64/reloc.h)
- [LLD 22.1.8 TBD compatibility](https://github.com/llvm/llvm-project/blob/llvmorg-22.1.8/lld/MachO/InputFiles.cpp)
