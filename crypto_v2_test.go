package atxp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/atendi9/capivara/assert"
)

// Cross-language known-answer vectors. The exact same vectors are asserted in
// the Node.js test suite (atxp.test.js), proving Go and JS use byte-identical
// PBKDF2-HMAC-SHA256 and AES-256-GCM primitives.
const (
	katPBKDF2 = "c30e125ad616b2f56073aca70bf0c0009177eca5e2553263a1c8de8e1c63d684"
	katGCM    = "66a2b1399775301e0dd42545400842bddb19187c"
)

// TestKATPBKDF2 pins the PBKDF2 output for ("pw", 16 zero bytes, 1 iter, 32 B).
func TestKATPBKDF2(t *testing.T) {
	key, err := deriveKey("pw", make([]byte, SaltSize), 1)
	assert.NoError(t, err)
	assert.Equal(t, katPBKDF2, hex.EncodeToString(key))
}

// TestKATGCM pins the AES-256-GCM ciphertext||tag for fixed key/nonce/plaintext.
func TestKATGCM(t *testing.T) {
	block, err := aes.NewCipher(bytes.Repeat([]byte{0x01}, KeySize))
	assert.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	assert.NoError(t, err)
	out := aead.Seal(nil, bytes.Repeat([]byte{0x02}, NonceSize), []byte("atxp"), nil)
	assert.Equal(t, katGCM, hex.EncodeToString(out))
}

// newTestCipher derives a cipher from a fixed password/salt for deterministic
// tests, using a low iteration count to keep tests fast.
func newTestCipher(t *testing.T, password string, salt []byte) Cipher {
	t.Helper()
	key, err := deriveKey(password, salt, 1)
	assert.NoError(t, err)
	c, err := newGCMCipher(key)
	assert.NoError(t, err)
	return c
}

// TestDeriveKey validates PBKDF2 key derivation determinism and input checks.
func TestDeriveKey(t *testing.T) {
	salt := bytes.Repeat([]byte{0xAB}, SaltSize)

	t.Run("deterministic for same inputs", func(t *testing.T) {
		k1, err := deriveKey("secret", salt, 10)
		assert.NoError(t, err)
		k2, err := deriveKey("secret", salt, 10)
		assert.NoError(t, err)
		assert.Equal(t, KeySize, len(k1))
		assert.Equal(t, string(k1), string(k2))
	})

	t.Run("different password yields different key", func(t *testing.T) {
		k1, _ := deriveKey("secret", salt, 10)
		k2, _ := deriveKey("other", salt, 10)
		assert.True(t, string(k1) != string(k2))
	})

	t.Run("rejects wrong salt size", func(t *testing.T) {
		_, err := deriveKey("secret", []byte("short"), 10)
		assert.ErrorIs(t, err, ErrHandshake)
	})

	t.Run("non-positive iterations falls back to default", func(t *testing.T) {
		k, err := deriveKey("secret", salt, 0)
		assert.NoError(t, err)
		assert.Equal(t, KeySize, len(k))
	})
}

// TestNewGCMCipher validates key length enforcement.
func TestNewGCMCipher(t *testing.T) {
	t.Run("rejects wrong key length", func(t *testing.T) {
		_, err := newGCMCipher([]byte("too-short"))
		assert.ErrorIs(t, err, ErrInvalidKey)
	})

	t.Run("accepts 32-byte key", func(t *testing.T) {
		c, err := newGCMCipher(bytes.Repeat([]byte{0x01}, KeySize))
		assert.NoError(t, err)
		assert.NotNil(t, c)
	})
}

// TestCipherRoundTrip validates Seal/Open symmetry and binary safety.
func TestCipherRoundTrip(t *testing.T) {
	salt := bytes.Repeat([]byte{0x01}, SaltSize)
	c := newTestCipher(t, "password", salt)

	plaintext := []byte{0x00, 0x09, 0x0A, 0x0A, '%', 'P', 'D', 'F', 0xFF}
	sealed, err := c.Seal(plaintext)
	assert.NoError(t, err)
	assert.True(t, len(sealed) >= NonceSize+GCMTagSize)

	opened, err := c.Open(sealed)
	assert.NoError(t, err)
	assert.Equal(t, string(plaintext), string(opened))
}

// TestCipherNonceUniqueness ensures two seals of the same plaintext differ.
func TestCipherNonceUniqueness(t *testing.T) {
	c := newTestCipher(t, "password", bytes.Repeat([]byte{0x02}, SaltSize))
	a, _ := c.Seal([]byte("same"))
	b, _ := c.Seal([]byte("same"))
	assert.True(t, !bytes.Equal(a, b))
}

// TestCipherWrongPassword ensures a cipher derived from a different password
// cannot open the frame, with an indistinguishable error.
func TestCipherWrongPassword(t *testing.T) {
	salt := bytes.Repeat([]byte{0x03}, SaltSize)
	good := newTestCipher(t, "right-password", salt)
	bad := newTestCipher(t, "wrong-password", salt)

	sealed, err := good.Seal([]byte("top secret"))
	assert.NoError(t, err)

	_, err = bad.Open(sealed)
	assert.ErrorIs(t, err, ErrInvalidChecksum)
}

// TestCipherTamperDetection ensures any modification fails authentication.
func TestCipherTamperDetection(t *testing.T) {
	c := newTestCipher(t, "password", bytes.Repeat([]byte{0x04}, SaltSize))
	sealed, err := c.Seal([]byte("integrity protected"))
	assert.NoError(t, err)

	sealed[len(sealed)-1] ^= 0xFF
	_, err = c.Open(sealed)
	assert.ErrorIs(t, err, ErrInvalidChecksum)
}

// TestCipherOpenTooSmall ensures undersized frames are rejected before AEAD.
func TestCipherOpenTooSmall(t *testing.T) {
	c := newTestCipher(t, "password", bytes.Repeat([]byte{0x05}, SaltSize))
	_, err := c.Open(make([]byte, NonceSize+GCMTagSize-1))
	assert.ErrorIs(t, err, ErrFrameTooSmall)
}
