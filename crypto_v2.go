// Package atxp implements the ATXP (Atendi9 Transmission Exchange Protocol) wire protocol framing and transport layer.
//   - Copyright (c) 2026 Atendi9
package atxp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// Cryptographic sizing constants for the ATXP V2 secure layer. None of these
// are magic numbers: they are fixed by the chosen primitives (AES-256-GCM,
// PBKDF2-HMAC-SHA256).
const (
	// SaltSize is the length in bytes of the per-connection PBKDF2 salt.
	SaltSize = 16
	// NonceSize is the AES-GCM standard nonce length in bytes.
	NonceSize = 12
	// KeySize is the AES-256 key length in bytes.
	KeySize = 32
	// GCMTagSize is the AES-GCM authentication tag length in bytes.
	GCMTagSize = 16
	// DefaultKDFIterations is the default PBKDF2 iteration count. It follows the
	// OWASP recommendation for PBKDF2-HMAC-SHA256 and is applied once per
	// connection (not per frame) so the cost is bounded.
	DefaultKDFIterations = 600_000
)

// Cipher seals and opens ATXP V2 frame payloads using an authenticated
// encryption scheme. Implementations are safe for concurrent use.
//
// Seal returns the concatenation nonce || ciphertext || tag. Open expects that
// same layout and returns the recovered plaintext, or [ErrInvalidChecksum] when
// authentication fails (wrong key or tampering).
type Cipher interface {
	Seal(plaintext []byte) ([]byte, error)
	Open(nonceAndCiphertext []byte) ([]byte, error)
}

// gcmCipher is the AES-256-GCM implementation of [Cipher]. It is unexported;
// callers obtain it through a handshake or [newGCMCipher].
type gcmCipher struct {
	aead cipher.AEAD
}

var _ Cipher = (*gcmCipher)(nil)

// deriveKey derives a 32-byte AES-256 key from a password and salt using
// PBKDF2-HMAC-SHA256. The password itself is never transmitted; both peers
// derive the same key independently from the shared secret and the salt
// exchanged during the handshake.
func deriveKey(password string, salt []byte, iterations int) ([]byte, error) {
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("atxp.deriveKey: %w", ErrHandshake)
	}
	if iterations <= 0 {
		iterations = DefaultKDFIterations
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, KeySize)
	if err != nil {
		return nil, fmt.Errorf("atxp.deriveKey: %w", err)
	}
	return key, nil
}

// newGCMCipher builds an AES-256-GCM [Cipher] from a 32-byte key.
func newGCMCipher(key []byte) (Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("atxp.newGCMCipher: %w", ErrInvalidKey)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("atxp.newGCMCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("atxp.newGCMCipher: %w", err)
	}
	return &gcmCipher{aead: aead}, nil
}

// Seal encrypts plaintext with a fresh random 12-byte nonce read from
// crypto/rand and returns nonce || ciphertext || tag. A unique nonce per call
// is required for GCM security.
func (g *gcmCipher) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("atxp.Seal: nonce generation: %w", err)
	}
	// Prefix the nonce; Seal appends ciphertext+tag onto the nonce slice.
	return g.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open authenticates and decrypts a frame previously produced by Seal. It
// returns [ErrInvalidChecksum] when authentication fails for any reason.
func (g *gcmCipher) Open(nonceAndCiphertext []byte) ([]byte, error) {
	if len(nonceAndCiphertext) < NonceSize+GCMTagSize {
		return nil, fmt.Errorf("atxp.Open: %w", ErrFrameTooSmall)
	}
	nonce := nonceAndCiphertext[:NonceSize]
	ciphertext := nonceAndCiphertext[NonceSize:]
	plaintext, err := g.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Do not leak the underlying reason; wrong key and tampering must be
		// indistinguishable to the caller.
		return nil, ErrInvalidChecksum
	}
	return plaintext, nil
}
