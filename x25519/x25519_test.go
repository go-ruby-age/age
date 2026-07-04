// Copyright (c) the go-ruby-age/age authors
//
// SPDX-License-Identifier: BSD-3-Clause

package x25519_test

import (
	"errors"
	"strings"
	"testing"

	fage "filippo.io/age"

	age "github.com/go-ruby-age/age"
	"github.com/go-ruby-age/age/x25519"
)

func TestGenerateAndStrings(t *testing.T) {
	id, err := x25519.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.HasPrefix(id.String(), "AGE-SECRET-KEY-1") {
		t.Fatalf("identity string: %q", id.String())
	}
	pub := id.ToPublic()
	if !strings.HasPrefix(pub.String(), "age1") {
		t.Fatalf("recipient string: %q", pub.String())
	}
	// Round-trip the string forms back through the parsers.
	if _, err := x25519.ParseIdentity(id.String()); err != nil {
		t.Fatalf("parse identity: %v", err)
	}
	if _, err := x25519.ParseRecipient(pub.String()); err != nil {
		t.Fatalf("parse recipient: %v", err)
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := x25519.ParseIdentity("AGE-SECRET-KEY-1-bogus"); !errors.Is(err, age.ErrParse) {
		t.Fatalf("identity parse: want ErrParse, got %v", err)
	}
	if _, err := x25519.ParseRecipient("age1bogus"); !errors.Is(err, age.ErrParse) {
		t.Fatalf("recipient parse: want ErrParse, got %v", err)
	}
}

// TestGenerateFailure drives the otherwise-unreachable randomness-failure branch
// of Generate through the package's generate seam.
func TestGenerateFailure(t *testing.T) {
	orig := x25519.SetGenerateForTest(func() (*fage.X25519Identity, error) {
		return nil, errors.New("no entropy")
	})
	defer x25519.SetGenerateForTest(orig)
	if _, err := x25519.Generate(); !errors.Is(err, age.ErrParse) {
		t.Fatalf("want ErrParse from generate failure, got %v", err)
	}
}
