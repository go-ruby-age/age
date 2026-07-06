<p align="center"><img src="https://raw.githubusercontent.com/go-ruby-age/brand/main/social/go-ruby-age-age.png" alt="go-ruby-age/age" width="720"></p>

# age — go-ruby-age

[![Docs](https://img.shields.io/badge/docs-mkdocs--material-DC2626)](https://go-ruby-age.github.io/docs/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo) reimplementation of Ruby's [`age`](https://github.com/FiloSottile/typage)
gem** — the binding for the [age](https://age-encryption.org) file-encryption
format. It mirrors the gem's public surface (`Age.encrypt` / `Age.decrypt`, the
`Age::X25519` and `Age::Scrypt` recipient/identity types, ASCII armor, the
streaming `Age::Encryptor` / `Age::Decryptor` and the `Age::Error` tree) and
produces files the reference `age` CLI reads — and reads files it writes —
**without any Ruby runtime**.

It is a sibling of [go-ruby-bcrypt](https://github.com/go-ruby-bcrypt/bcrypt)
(OpenBSD bcrypt), [go-ruby-regexp](https://github.com/go-ruby-regexp/regexp)
(the Onigmo engine) and [go-ruby-erb](https://github.com/go-ruby-erb/erb) (the
ERB compiler), and is intended as the age backend for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby).

## Built on the reference implementation

The age format and its cryptography are provided by
[`filippo.io/age`](https://pkg.go.dev/filippo.io/age) — the reference age
implementation written by age's author — and its `age/armor` package. This
module does **not** reimplement the format or the crypto; it is a faithful,
Ruby-shaped façade over it. Because the primitives (ChaCha20-Poly1305, X25519,
scrypt) are endian-independent, the package is byte-identical on every supported
architecture, big- or little-endian.

## Ruby-faithful surface

| Ruby (`age` gem)                       | This package                                          |
| -------------------------------------- | ----------------------------------------------------- |
| `Age.encrypt(pt, recipients:)`         | `age.Encrypt(pt, []age.Recipient{…})`                 |
| `Age.encrypt(pt, …, armor: true)`      | `age.Encrypt(pt, …, age.WithArmor())`                 |
| `Age.decrypt(ct, identities:)`         | `age.Decrypt(ct, []age.Identity{…})`                  |
| `Age::X25519::Identity.generate`       | `x25519.Generate()`                                   |
| `Age::X25519::Identity#to_public`      | `(*x25519.Identity).ToPublic()`                       |
| `Age::X25519::Identity#to_s`           | `(*x25519.Identity).String()` → `AGE-SECRET-KEY-1…`   |
| `Age::X25519::Recipient.from_string`   | `x25519.ParseRecipient("age1…")`                      |
| `Age::Scrypt::Recipient.new(pass)`     | `scrypt.NewRecipient(pass)` + `SetWorkFactor(logN)`   |
| `Age::Scrypt::Identity.new(pass)`      | `scrypt.NewIdentity(pass)` + `SetMaxWorkFactor(logN)` |
| `Age::Encryptor` / `Age::Decryptor`    | `age.Encryptor` / `age.Decryptor` (IO wrappers)       |
| `Age::Error` (base)                    | `age.Err` (wrapped by every error)                    |
| `NoIdentityMatchError`                 | `age.ErrNoIdentityMatch`                              |
| bad passphrase                         | `age.ErrIncorrectPassphrase`                          |
| parse / format errors                  | `age.ErrParse` / `age.ErrFormat`                      |

## Install

```sh
go get github.com/go-ruby-age/age
```

## Usage

```go
package main

import (
	"fmt"

	"github.com/go-ruby-age/age"
	"github.com/go-ruby-age/age/scrypt"
	"github.com/go-ruby-age/age/x25519"
)

func main() {
	// X25519 key pair.
	id, _ := x25519.Generate()
	fmt.Println(id.String())            // AGE-SECRET-KEY-1…
	fmt.Println(id.ToPublic().String()) // age1…

	// Encrypt to the recipient, decrypt with the identity.
	ct, _ := age.Encrypt([]byte("hello"), []age.Recipient{id.ToPublic()})
	pt, _ := age.Decrypt(ct, []age.Identity{id})
	fmt.Println(string(pt)) // hello

	// ASCII armor.
	armored, _ := age.Encrypt([]byte("hi"), []age.Recipient{id.ToPublic()}, age.WithArmor())
	fmt.Println(string(armored[:33])) // -----BEGIN AGE ENCRYPTED FILE-----

	// Passphrase (scrypt) — an scrypt recipient must be the only recipient.
	r, _ := scrypt.NewRecipient("correct horse battery staple")
	sct, _ := age.Encrypt([]byte("secret"), []age.Recipient{r})
	sid, _ := scrypt.NewIdentity("correct horse battery staple")
	spt, _ := age.Decrypt(sct, []age.Identity{sid})
	fmt.Println(string(spt)) // secret
}
```

## Tests & coverage

The suite is self-contained and deterministic: X25519 and scrypt round-trips
(binary and armored), multiple-recipient decryption, wrong-identity and
wrong-passphrase rejection, tampered-ciphertext authentication failure, and the
streaming wrappers — plus **interop test vectors** frozen from the reference
`age` tool (a binary message, an armored message and a passphrase message, all
decrypted here against a fixed key), and a check that our own output is read
back by `filippo.io/age` directly. No Ruby, no `age` CLI and no network are
needed, so every platform lane holds the gate at **100 % coverage**.

```sh
COVERPKG=$(go list ./... | paste -sd, -)
go test -race -coverpkg="$COVERPKG" -coverprofile=cover.out ./...
go tool cover -func=cover.out | tail -1   # 100.0%
```

CGO-free, `gofmt` + `go vet` clean, and green across the six 64-bit Go targets
(amd64, arm64, riscv64, loong64, ppc64le, s390x — the last big-endian).

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright the go-ruby-age/age authors.

## WebAssembly

Being pure Go (CGO=0), this library also compiles to **WebAssembly** — both
`GOOS=js GOARCH=wasm` (browser / Node.js) and `GOOS=wasip1 GOARCH=wasm` (WASI).
CI builds both targets on every push, alongside the six 64-bit native/qemu arches.

```sh
GOOS=js     GOARCH=wasm go build ./...   # browser / Node
GOOS=wasip1 GOARCH=wasm go build ./...   # WASI (wasmtime, wasmer, wasmedge, …)
```
