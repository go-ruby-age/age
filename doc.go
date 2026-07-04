// Copyright (c) the go-ruby-age/age authors
//
// SPDX-License-Identifier: BSD-3-Clause

// Package age is a pure-Go (no cgo) reimplementation of Ruby's age gem — the
// binding for the age file-encryption format (https://age-encryption.org).
//
// It mirrors the gem's public surface: the Age.encrypt / Age.decrypt one-shots,
// the Age::X25519 and Age::Scrypt recipient/identity types, ASCII armor, the
// streaming Age::Encryptor / Age::Decryptor IO wrappers and the Age::Error
// exception tree. The format and cryptography are provided by filippo.io/age,
// the reference age implementation written by age's author, so files produced
// here are read by the reference age CLI and vice-versa — without any Ruby
// runtime.
//
// # Quick start
//
//	id, _ := x25519.Generate()
//	ct, _ := age.Encrypt([]byte("hello"), []age.Recipient{id.ToPublic()})
//	pt, _ := age.Decrypt(ct, []age.Identity{id})
//	string(pt) // "hello"
//
// The age format and its ChaCha20-Poly1305 / X25519 / scrypt primitives are
// endian-independent, so the package is byte-identical on every supported
// architecture, big- or little-endian.
package age

// Version is the version of this Go port. It is independent of the upstream
// Ruby age gem's version.
const Version = "0.1.0"
