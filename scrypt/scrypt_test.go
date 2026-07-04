// Copyright (c) the go-ruby-age/age authors
//
// SPDX-License-Identifier: BSD-3-Clause

package scrypt_test

import (
	"errors"
	"testing"

	age "github.com/go-ruby-age/age"
	"github.com/go-ruby-age/age/scrypt"
)

func TestConstructorsAndTuning(t *testing.T) {
	r, err := scrypt.NewRecipient("hunter2")
	if err != nil {
		t.Fatalf("new recipient: %v", err)
	}
	r.SetWorkFactor(11)

	id, err := scrypt.NewIdentity("hunter2")
	if err != nil {
		t.Fatalf("new identity: %v", err)
	}
	id.SetMaxWorkFactor(20)
}

func TestEmptyPassphrase(t *testing.T) {
	if _, err := scrypt.NewRecipient(""); !errors.Is(err, age.ErrParse) {
		t.Fatalf("recipient: want ErrParse, got %v", err)
	}
	if _, err := scrypt.NewIdentity(""); !errors.Is(err, age.ErrParse) {
		t.Fatalf("identity: want ErrParse, got %v", err)
	}
}
