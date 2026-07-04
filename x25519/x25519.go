// Copyright (c) the go-ruby-age/age authors
//
// SPDX-License-Identifier: BSD-3-Clause

// Package x25519 mirrors the gem's Age::X25519 namespace: native age X25519
// key-pair recipients and identities, whose string forms are the familiar
// "age1…" recipients and "AGE-SECRET-KEY-1…" identities.
package x25519

import (
	"fmt"

	ruby "github.com/go-ruby-age/age"

	fage "filippo.io/age"
)

// generate is the key-pair source, indirected so tests can drive the
// (otherwise unreachable) randomness-failure branch of Generate.
var generate = fage.GenerateX25519Identity

// Recipient is an X25519 public recipient (Age::X25519::Recipient). Its String
// form is an "age1…" recipient. It satisfies age.Recipient.
type Recipient struct {
	*fage.X25519Recipient
}

// Identity is an X25519 key pair (Age::X25519::Identity). Its String form is an
// "AGE-SECRET-KEY-1…" secret key. It satisfies age.Identity.
type Identity struct {
	*fage.X25519Identity
}

// Generate creates a fresh X25519 key pair, mirroring
// Age::X25519::Identity.generate.
func Generate() (*Identity, error) {
	id, err := generate()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ruby.ErrParse, err)
	}
	return &Identity{id}, nil
}

// ParseIdentity parses an "AGE-SECRET-KEY-1…" secret key.
func ParseIdentity(s string) (*Identity, error) {
	id, err := fage.ParseX25519Identity(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ruby.ErrParse, err)
	}
	return &Identity{id}, nil
}

// ParseRecipient parses an "age1…" recipient, mirroring
// Age::X25519::Recipient.from_string.
func ParseRecipient(s string) (*Recipient, error) {
	r, err := fage.ParseX25519Recipient(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ruby.ErrParse, err)
	}
	return &Recipient{r}, nil
}

// ToPublic returns the public recipient for this identity, mirroring
// Age::X25519::Identity#to_public.
func (i *Identity) ToPublic() *Recipient {
	return &Recipient{i.X25519Identity.Recipient()}
}
