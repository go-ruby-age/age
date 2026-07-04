// Copyright (c) the go-ruby-age/age authors
//
// SPDX-License-Identifier: BSD-3-Clause

package age

import (
	"errors"
	"fmt"

	fage "filippo.io/age"
)

// The package's sentinel errors mirror the exception hierarchy of the Ruby age
// gem, whose classes descend from Age::Error. Every error returned by the
// package wraps Err, so a caller can match the whole family with
// errors.Is(err, age.Err) — the Go equivalent of "rescue Age::Error" — or match
// a specific member for finer control.
var (
	// Err is the base sentinel every other error in the package wraps, mirroring
	// the gem's Age::Error base class.
	Err = errors.New("age")

	// ErrNoIdentityMatch is returned by Decrypt when none of the supplied
	// identities could unwrap the file key, mirroring the gem's
	// Age::NoMatchingKeys (age's NoIdentityMatchError).
	ErrNoIdentityMatch = fmt.Errorf("%w: no identity matched any recipient stanza", Err)

	// ErrIncorrectPassphrase is returned by Decrypt when a passphrase-encrypted
	// (scrypt) file is decrypted with the wrong passphrase.
	ErrIncorrectPassphrase = fmt.Errorf("%w: incorrect passphrase", Err)

	// ErrParse is returned when a key string, recipient or passphrase cannot be
	// parsed, mirroring the gem's parse/format errors.
	ErrParse = fmt.Errorf("%w: parse error", Err)

	// ErrFormat is returned when a ciphertext is malformed, truncated or has been
	// tampered with (authentication failure), mirroring the gem's decrypt error.
	ErrFormat = fmt.Errorf("%w: malformed or corrupt ciphertext", Err)

	// ErrEncrypt is returned when encryption cannot proceed, for example when no
	// recipients are given or an scrypt recipient is combined with another
	// recipient (age requires an scrypt recipient to be the only one).
	ErrEncrypt = fmt.Errorf("%w: encryption failed", Err)
)

// translate maps a filippo.io/age decryption error onto the package's sentinel
// tree. A NoIdentityMatchError over a lone scrypt stanza is reported as an
// incorrect passphrase; any other no-match is ErrNoIdentityMatch; everything
// else (bad header, truncation, authentication failure) is ErrFormat.
func translate(err error) error {
	var nim *fage.NoIdentityMatchError
	if errors.As(err, &nim) {
		if len(nim.StanzaTypes) == 1 && nim.StanzaTypes[0] == "scrypt" {
			return fmt.Errorf("%w: %v", ErrIncorrectPassphrase, err)
		}
		return fmt.Errorf("%w: %v", ErrNoIdentityMatch, err)
	}
	return fmt.Errorf("%w: %v", ErrFormat, err)
}
