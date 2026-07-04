// Copyright (c) the go-ruby-age/age authors
//
// SPDX-License-Identifier: BSD-3-Clause

package x25519

import fage "filippo.io/age"

// SetGenerateForTest swaps the key-pair source used by Generate and returns the
// previous one, so tests can exercise the randomness-failure branch that is
// otherwise unreachable with a working entropy source.
func SetGenerateForTest(fn func() (*fage.X25519Identity, error)) func() (*fage.X25519Identity, error) {
	prev := generate
	generate = fn
	return prev
}
