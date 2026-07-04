// Copyright (c) the go-ruby-age/age authors
//
// SPDX-License-Identifier: BSD-3-Clause

package age

import (
	"bufio"
	"fmt"
	"io"

	fage "filippo.io/age"
	"filippo.io/age/armor"
)

// Encryptor streams encryption to an underlying io.Writer, mirroring the gem's
// Age::Encryptor. Write encrypted chunks with Write and finish the message with
// Close (which flushes the final chunk and, when armored, the trailing footer);
// Close must be called for the output to be valid. It implements io.WriteCloser.
type Encryptor struct {
	w   io.WriteCloser
	arm io.WriteCloser // non-nil when armored, closed after w
}

// NewEncryptor starts an age message on dst encrypted to the given recipients,
// mirroring Age::Encryptor.new. With WithArmor the message is ASCII-armored.
func NewEncryptor(dst io.Writer, recipients []Recipient, opts ...Option) (*Encryptor, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	out := dst
	var arm io.WriteCloser
	if o.armor {
		arm = armor.NewWriter(dst)
		out = arm
	}
	w, err := fage.Encrypt(out, recipients...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncrypt, err)
	}
	return &Encryptor{w: w, arm: arm}, nil
}

// Write encrypts and writes p. Written data is buffered into fixed-size chunks
// and only guaranteed to reach the underlying writer once Close is called.
func (e *Encryptor) Write(p []byte) (int, error) {
	return e.w.Write(p)
}

// Close flushes the final chunk and, for an armored stream, the ASCII footer. It
// must be called to produce a valid message.
func (e *Encryptor) Close() error {
	err := e.w.Close()
	if e.arm != nil && err == nil {
		err = e.arm.Close()
	}
	return err
}

// Decryptor streams decryption from an underlying io.Reader, mirroring the gem's
// Age::Decryptor. Binary and ASCII-armored input are detected automatically. It
// implements io.Reader.
type Decryptor struct {
	r io.Reader
}

// NewDecryptor begins decrypting the age message read from src with the given
// identities, mirroring Age::Decryptor.new. It fails immediately with
// ErrNoIdentityMatch / ErrIncorrectPassphrase when the header cannot be
// unwrapped, or ErrFormat when the header is malformed.
func NewDecryptor(src io.Reader, identities []Identity) (*Decryptor, error) {
	br := bufio.NewReader(src)
	var in io.Reader = br
	if p, _ := br.Peek(len(armor.Header)); string(p) == armor.Header {
		in = armor.NewReader(br)
	}
	r, err := fage.Decrypt(in, identities...)
	if err != nil {
		return nil, translate(err)
	}
	return &Decryptor{r: r}, nil
}

// Read decrypts into p. A tampered or truncated payload surfaces here as an
// ErrFormat authentication failure.
func (d *Decryptor) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	if err != nil && err != io.EOF {
		return n, translate(err)
	}
	return n, err
}
