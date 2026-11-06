# golink

A small, independent native linker written in Go. It consumes native objects
emitted by the official Go linker and small precompiled native support objects.
It does not patch Go, compile C, discover an SDK, or implement UI policy.

The current implementation is experimental and supports **Android ARM64 ELF**.
iOS Mach-O is planned. It is not a general replacement for LLVM LLD or GNU ld.

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
explicit target ELF inputs; no host library search occurs. `soname` is optional.
`entry` is reserved for controlled native PIE probes, not general executable
linking. The caller owns target input provenance, Go version and ABI matching.
Unknown request fields, targets, section features and relocations are errors.
Failed linking preserves the previous output. Output contains no DWARF sections,
including when the Go compiler generated debug input.

The Go API exposes `ReadRequest` and `Link`. All link state belongs to a single
invocation. The CLI request protocol is independent of GOUI and LLD syntax.

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
consumer project; they do not imply arbitrary Go version, physical device or
iOS support. Final publication requires source review and a stable release.

## References

The implementation reads native ELF structures through Go's `debug/elf`.
It was written independently; no Go toolchain fork or LLD source is included.
Applicable references:

- [AAELF64 ABI](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst)
- [Go 1.25.8 external-link driver](https://github.com/golang/go/blob/go1.25.8/src/cmd/link/internal/ld/lib.go)
- [Android Bionic ELF loader](https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/linker_phdr.cpp)
