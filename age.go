// Copyright (c) the go-ruby-age/age authors
//
// SPDX-License-Identifier: BSD-3-Clause

package age

import (
	"bytes"
	"io"

	fage "filippo.io/age"
)

// Recipient is a party a message can be encrypted to (an age recipient). The
// X25519 and scrypt recipient types satisfy it, mirroring the objects passed to
// the gem's Age.encrypt(recipients:) keyword.
type Recipient = fage.Recipient

// Identity is a key that can decrypt a message (an age identity). The X25519 and
// scrypt identity types satisfy it, mirroring the objects passed to the gem's
// Age.decrypt(identities:) keyword.
type Identity = fage.Identity

// Option configures Encrypt / NewEncryptor. It mirrors the keyword arguments of
// the gem's Age.encrypt.
type Option func(*options)

type options struct {
	armor bool
}

// WithArmor selects PEM-style ASCII "armor" output, wrapping the binary age
// message in "-----BEGIN AGE ENCRYPTED FILE-----" … "-----END AGE ENCRYPTED
// FILE-----". It mirrors Age.encrypt(..., armor: true).
func WithArmor() Option {
	return func(o *options) { o.armor = true }
}

// Encrypt encrypts plaintext to the given recipients and returns the complete
// age message, mirroring the gem's Age.encrypt(plaintext, recipients:). With
// WithArmor the output is ASCII-armored. Any identity holding a private key for
// one of the recipients can later Decrypt it.
func Encrypt(plaintext []byte, recipients []Recipient, opts ...Option) ([]byte, error) {
	var buf bytes.Buffer
	if err := encryptTo(&buf, plaintext, recipients, opts...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// encryptTo streams the encryption of plaintext into dst. It is the shared core
// of Encrypt and lets tests drive the streaming write/close error paths through
// a failing writer.
func encryptTo(dst io.Writer, plaintext []byte, recipients []Recipient, opts ...Option) error {
	enc, err := NewEncryptor(dst, recipients, opts...)
	if err != nil {
		return err
	}
	if _, err := enc.Write(plaintext); err != nil {
		return err
	}
	return enc.Close()
}

// Decrypt decrypts an age message (binary or ASCII-armored — the framing is
// detected automatically) using the given identities and returns the plaintext,
// mirroring the gem's Age.decrypt(ciphertext, identities:). It returns
// ErrNoIdentityMatch when no identity matches, ErrIncorrectPassphrase for a
// wrong scrypt passphrase and ErrFormat when the message is corrupt or has been
// tampered with.
func Decrypt(ciphertext []byte, identities []Identity) ([]byte, error) {
	dec, err := NewDecryptor(bytes.NewReader(ciphertext), identities)
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(dec)
	if err != nil {
		return nil, err
	}
	return out, nil
}
