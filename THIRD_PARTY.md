# Third-party source notices

`internal/codesign/codesign.go` is adapted from Go 1.25.8,
`src/cmd/internal/codesign/codesign.go`, copyright The Go Authors, under the BSD
license included in `internal/codesign/LICENSE`. The internal hash-size constant
is replaced by `crypto/sha256.Size`. No Go toolchain patch is required.
