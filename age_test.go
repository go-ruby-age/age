// Copyright (c) the go-ruby-age/age authors
//
// SPDX-License-Identifier: BSD-3-Clause

package age_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	fage "filippo.io/age"

	age "github.com/go-ruby-age/age"
	"github.com/go-ruby-age/age/scrypt"
	"github.com/go-ruby-age/age/x25519"
)

// Interop test vectors produced offline by the reference age CLI / library
// (filippo.io/age v1.3.1). The X25519 key pair below is fixed so decryption is
// deterministic. vectorPlain is the plaintext all three vectors encrypt.
const (
	vectorIdentity  = "AGE-SECRET-KEY-1V3AXS57C4TPJARPJ7CUPCTJPHRPVXGHM5ZAEKCSMLZWD7UX6DP2QD07G2Y"
	vectorRecipient = "age1h939xrn7xx52x5gqcw3g6zxudrhx46gvmvy9wwd4ggeakherhcxskf7vjq"
	vectorPlain     = "the quick brown fox jumps over the lazy dog"

	// Binary age message encrypted to vectorRecipient by the reference `age` CLI.
	vectorX25519B64 = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBMZW90NDBBTG1waHhHSU9HMUNlbDdyVDZneTFmRytTT2lCMU93R3E3L1VnCnJCOW5jTnBJSDBoNDJWbGJGVWhVOXZGU3Zhc3ptSTVxSkxpVGVEQ3ViS3MKLS0tIDg5M252bUVVa1JkbFBJSmZ6Mm1HV0VxOEhBbEFXQ3VaMElKMG9mc25reE0KotJmPbDVsl/+oqM0/q2UguG3aTZJr4S0nZnbRAiJ9TugUeO93HwbSKP3B/tDiia6wwNPdEunPV2Q7/+GxGMlUysObBsHy+GR+/oi"

	// ASCII-armored age message encrypted to vectorRecipient by the reference CLI.
	vectorX25519Armor = `-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBSbVIwNXRxTUllRzgwUml1
SFh6a21Fd2RaRW5OZkVOSUEwbzZtdnRPUm5RCk14UFAwV3ZKdUpxalFLR2xuKzBu
cStFMTN1dmQ5d0xpVmNaZWl5dlhQQ1kKLS0tIFdRR0dud0oxbXpQVEZWdGR6RTUw
K1ZjNUZESXZiOG9QOFlGWnoraXF3WFUK8h+PiZqPmCivpD2gURaPG4mfwiMuvX6D
KTSFl1sq8A0FpesclUz0ytl9SN9qE7PIcXqW4e5JP2b0UaLa4V8JAnxtMygnxhXx
ULnm
-----END AGE ENCRYPTED FILE-----
`

	// scrypt (passphrase) age message, passphrase vectorPassphrase, work factor
	// 10, produced by the reference library.
	vectorPassphrase = "correct horse battery staple"
	vectorScryptB64  = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB6SVQyU0hzWVVXK21sWUxQbE5QREpBIDEwCk9MdHZBZ2pERHc5M1gzL2dGWlI5ZDNSN2xmTFVsQXUvRTZTMTlNOEJYU1kKLS0tIFVqOXBHVGJCUXZHSE53d3BDRDdVV2h4RGtnSmpLVktWL1ZoYXdVaHJ5R00KK36fs0KapuVVhk2x52L4YDZXrJ+B+el1PnIR6IF2rTnLHvvsXKnyqa3FoMjV+2LIKRQz2pIRplvaY1pBNN+cOdzynuWKs+7VgSyN"
)

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	return b
}

// TestX25519RoundTrip covers binary and armored encrypt→decrypt with a freshly
// generated key pair.
func TestX25519RoundTrip(t *testing.T) {
	id, err := x25519.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for _, armored := range []bool{false, true} {
		var opts []age.Option
		if armored {
			opts = append(opts, age.WithArmor())
		}
		ct, err := age.Encrypt([]byte(vectorPlain), []age.Recipient{id.ToPublic()}, opts...)
		if err != nil {
			t.Fatalf("encrypt(armored=%v): %v", armored, err)
		}
		if armored != bytes.HasPrefix(ct, []byte("-----BEGIN AGE")) {
			t.Fatalf("armor framing mismatch (armored=%v): %q", armored, ct[:14])
		}
		pt, err := age.Decrypt(ct, []age.Identity{id})
		if err != nil {
			t.Fatalf("decrypt(armored=%v): %v", armored, err)
		}
		if string(pt) != vectorPlain {
			t.Fatalf("round trip mismatch: got %q", pt)
		}
	}
}

// TestMultipleRecipients checks any recipient's identity can decrypt.
func TestMultipleRecipients(t *testing.T) {
	a, _ := x25519.Generate()
	b, _ := x25519.Generate()
	ct, err := age.Encrypt([]byte(vectorPlain), []age.Recipient{a.ToPublic(), b.ToPublic()})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	for name, id := range map[string]age.Identity{"a": a, "b": b} {
		pt, err := age.Decrypt(ct, []age.Identity{id})
		if err != nil {
			t.Fatalf("decrypt with %s: %v", name, err)
		}
		if string(pt) != vectorPlain {
			t.Fatalf("decrypt with %s: got %q", name, pt)
		}
	}
}

// TestWrongIdentity checks a non-matching identity yields ErrNoIdentityMatch.
func TestWrongIdentity(t *testing.T) {
	a, _ := x25519.Generate()
	other, _ := x25519.Generate()
	ct, _ := age.Encrypt([]byte(vectorPlain), []age.Recipient{a.ToPublic()})
	_, err := age.Decrypt(ct, []age.Identity{other})
	if !errors.Is(err, age.ErrNoIdentityMatch) {
		t.Fatalf("want ErrNoIdentityMatch, got %v", err)
	}
	if !errors.Is(err, age.Err) {
		t.Fatalf("ErrNoIdentityMatch must wrap age.Err")
	}
}

// TestTamperedCiphertext checks a flipped payload byte fails authentication.
func TestTamperedCiphertext(t *testing.T) {
	id, _ := x25519.Generate()
	ct, _ := age.Encrypt([]byte(vectorPlain), []age.Recipient{id.ToPublic()})
	ct[len(ct)-1] ^= 0xff // corrupt the last payload byte
	_, err := age.Decrypt(ct, []age.Identity{id})
	if !errors.Is(err, age.ErrFormat) {
		t.Fatalf("want ErrFormat, got %v", err)
	}
}

// TestGarbageHeader checks non-age input is reported as ErrFormat.
func TestGarbageHeader(t *testing.T) {
	id, _ := x25519.Generate()
	_, err := age.Decrypt([]byte("this is not an age file"), []age.Identity{id})
	if !errors.Is(err, age.ErrFormat) {
		t.Fatalf("want ErrFormat, got %v", err)
	}
}

// TestScryptRoundTrip covers passphrase encrypt→decrypt, armored and binary.
func TestScryptRoundTrip(t *testing.T) {
	for _, armored := range []bool{false, true} {
		r, err := scrypt.NewRecipient(vectorPassphrase)
		if err != nil {
			t.Fatalf("new recipient: %v", err)
		}
		r.SetWorkFactor(10)
		var opts []age.Option
		if armored {
			opts = append(opts, age.WithArmor())
		}
		ct, err := age.Encrypt([]byte(vectorPlain), []age.Recipient{r}, opts...)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		id, err := scrypt.NewIdentity(vectorPassphrase)
		if err != nil {
			t.Fatalf("new identity: %v", err)
		}
		id.SetMaxWorkFactor(15)
		pt, err := age.Decrypt(ct, []age.Identity{id})
		if err != nil {
			t.Fatalf("decrypt(armored=%v): %v", armored, err)
		}
		if string(pt) != vectorPlain {
			t.Fatalf("scrypt round trip: got %q", pt)
		}
	}
}

// TestScryptWrongPassphrase checks a wrong passphrase yields ErrIncorrectPassphrase.
func TestScryptWrongPassphrase(t *testing.T) {
	r, _ := scrypt.NewRecipient(vectorPassphrase)
	r.SetWorkFactor(10)
	ct, _ := age.Encrypt([]byte(vectorPlain), []age.Recipient{r})
	id, _ := scrypt.NewIdentity("wrong passphrase")
	_, err := age.Decrypt(ct, []age.Identity{id})
	if !errors.Is(err, age.ErrIncorrectPassphrase) {
		t.Fatalf("want ErrIncorrectPassphrase, got %v", err)
	}
}

// TestScryptMustBeOnlyRecipient checks combining scrypt with X25519 fails.
func TestScryptMustBeOnlyRecipient(t *testing.T) {
	r, _ := scrypt.NewRecipient(vectorPassphrase)
	x, _ := x25519.Generate()
	_, err := age.Encrypt([]byte(vectorPlain), []age.Recipient{r, x.ToPublic()})
	if !errors.Is(err, age.ErrEncrypt) {
		t.Fatalf("want ErrEncrypt, got %v", err)
	}
}

// TestNoRecipients checks encrypting to nobody fails.
func TestNoRecipients(t *testing.T) {
	_, err := age.Encrypt([]byte(vectorPlain), nil)
	if !errors.Is(err, age.ErrEncrypt) {
		t.Fatalf("want ErrEncrypt, got %v", err)
	}
}

// TestInteropVectorX25519Binary decrypts a reference-CLI-produced binary message.
func TestInteropVectorX25519Binary(t *testing.T) {
	id, err := x25519.ParseIdentity(vectorIdentity)
	if err != nil {
		t.Fatalf("parse identity: %v", err)
	}
	pt, err := age.Decrypt(b64(t, vectorX25519B64), []age.Identity{id})
	if err != nil {
		t.Fatalf("decrypt vector: %v", err)
	}
	if string(pt) != vectorPlain {
		t.Fatalf("interop vector: got %q", pt)
	}
}

// TestInteropVectorX25519Armor decrypts a reference-CLI-produced armored message.
func TestInteropVectorX25519Armor(t *testing.T) {
	id, _ := x25519.ParseIdentity(vectorIdentity)
	pt, err := age.Decrypt([]byte(vectorX25519Armor), []age.Identity{id})
	if err != nil {
		t.Fatalf("decrypt armored vector: %v", err)
	}
	if string(pt) != vectorPlain {
		t.Fatalf("interop armored vector: got %q", pt)
	}
}

// TestInteropVectorScrypt decrypts a reference-produced passphrase message.
func TestInteropVectorScrypt(t *testing.T) {
	id, _ := scrypt.NewIdentity(vectorPassphrase)
	pt, err := age.Decrypt(b64(t, vectorScryptB64), []age.Identity{id})
	if err != nil {
		t.Fatalf("decrypt scrypt vector: %v", err)
	}
	if string(pt) != vectorPlain {
		t.Fatalf("interop scrypt vector: got %q", pt)
	}
}

// TestOutputReadByReference proves our output is consumed by the reference
// filippo.io/age library directly (not just our own wrapper).
func TestOutputReadByReference(t *testing.T) {
	id, _ := x25519.ParseIdentity(vectorIdentity)
	rid, err := fage.ParseX25519Identity(vectorIdentity)
	if err != nil {
		t.Fatalf("reference parse: %v", err)
	}
	ct, _ := age.Encrypt([]byte(vectorPlain), []age.Recipient{id.ToPublic()})
	r, err := fage.Decrypt(bytes.NewReader(ct), rid)
	if err != nil {
		t.Fatalf("reference decrypt: %v", err)
	}
	pt, _ := io.ReadAll(r)
	if string(pt) != vectorPlain {
		t.Fatalf("reference read our output: got %q", pt)
	}
}

// TestStreaming covers the Encryptor / Decryptor IO wrappers, armored.
func TestStreaming(t *testing.T) {
	id, _ := x25519.Generate()
	var buf bytes.Buffer
	enc, err := age.NewEncryptor(&buf, []age.Recipient{id.ToPublic()}, age.WithArmor())
	if err != nil {
		t.Fatalf("new encryptor: %v", err)
	}
	if _, err := io.WriteString(enc, vectorPlain); err != nil {
		t.Fatalf("stream write: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("stream close: %v", err)
	}
	dec, err := age.NewDecryptor(&buf, []age.Identity{id})
	if err != nil {
		t.Fatalf("new decryptor: %v", err)
	}
	pt, err := io.ReadAll(dec)
	if err != nil {
		t.Fatalf("stream read: %v", err)
	}
	if string(pt) != vectorPlain {
		t.Fatalf("streaming: got %q", pt)
	}
}

// failWriter accepts up to limit bytes across all writes, then errors — used to
// drive the streaming write-error path of encryptTo.
type failWriter struct {
	limit int
	n     int
}

func (w *failWriter) Write(p []byte) (int, error) {
	w.n += len(p)
	if w.n > w.limit {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

// TestEncryptWriteError drives the mid-stream flush failure so encryptTo returns
// the underlying write error. The header and nonce (< 4096 bytes) succeed; the
// large payload forces a chunk flush that overruns the writer's limit.
func TestEncryptWriteError(t *testing.T) {
	id, _ := x25519.Generate()
	big := bytes.Repeat([]byte("A"), 1<<18) // 256 KiB > one stream chunk
	// Route through the streaming core: the header + nonce (< 4096 B) succeed,
	// then the large payload forces a chunk flush that overruns the writer.
	err := age.EncryptToForTest(&failWriter{limit: 4096}, big, []age.Recipient{id.ToPublic()})
	if err == nil {
		t.Fatalf("expected a write error from the failing writer")
	}
}

// TestErrParseExported ensures the parse sentinel is reachable via the family
// root, matching the gem's "rescue Age::Error".
func TestErrParseExported(t *testing.T) {
	_, err := x25519.ParseRecipient("not-an-age-recipient")
	if !errors.Is(err, age.ErrParse) || !errors.Is(err, age.Err) {
		t.Fatalf("want ErrParse wrapping age.Err, got %v", err)
	}
}

// TestVersion pins the exported version constant.
func TestVersion(t *testing.T) {
	if !strings.HasPrefix(age.Version, "0.") {
		t.Fatalf("unexpected version %q", age.Version)
	}
}
