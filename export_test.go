// Copyright (c) the go-ruby-age/age authors
//
// SPDX-License-Identifier: BSD-3-Clause

package age

import "io"

// EncryptToForTest exposes the internal streaming core so tests can drive the
// mid-stream write-error path through a failing writer, which the buffer-backed
// public Encrypt can never trigger.
func EncryptToForTest(dst io.Writer, plaintext []byte, recipients []Recipient, opts ...Option) error {
	return encryptTo(dst, plaintext, recipients, opts...)
}
