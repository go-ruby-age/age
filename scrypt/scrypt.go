// Copyright (c) the go-ruby-age/age authors
//
// SPDX-License-Identifier: BSD-3-Clause

// Package scrypt mirrors the gem's Age::Scrypt namespace: passphrase-based age
// recipients and identities. An scrypt recipient must be the only recipient of
// a message.
package scrypt

import (
	"fmt"

	ruby "github.com/go-ruby-age/age"

	fage "filippo.io/age"
)

// Recipient encrypts a message under a passphrase (Age::Scrypt::Recipient). Its
// work factor (log2 of the scrypt cost) can be tuned with SetWorkFactor. It
// satisfies age.Recipient and must be the sole recipient of a message.
type Recipient struct {
	*fage.ScryptRecipient
}

// Identity decrypts a passphrase-encrypted message (Age::Scrypt::Identity). Its
// accepted maximum work factor can be tuned with SetMaxWorkFactor. It satisfies
// age.Identity.
type Identity struct {
	*fage.ScryptIdentity
}

// NewRecipient builds a passphrase recipient, mirroring
// Age::Scrypt::Recipient.new(passphrase). The passphrase must not be empty.
func NewRecipient(passphrase string) (*Recipient, error) {
	r, err := fage.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ruby.ErrParse, err)
	}
	return &Recipient{r}, nil
}

// NewIdentity builds a passphrase identity, mirroring
// Age::Scrypt::Identity.new(passphrase). The passphrase must not be empty.
func NewIdentity(passphrase string) (*Identity, error) {
	i, err := fage.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ruby.ErrParse, err)
	}
	return &Identity{i}, nil
}
