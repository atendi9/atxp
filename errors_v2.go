// Package atxp implements the ATXP (Atendi9 Transmission Exchange Protocol) wire protocol framing and transport layer.
//   - Copyright (c) 2026 Atendi9
package atxp

import "errors"

// Sentinel errors for the ATXP V2 secure protocol. Inspect them with
// [errors.Is]; never compare error strings directly.
var (
	// ErrFrameTooLarge is returned when an incoming frame announces a length
	// above MaxFrameSizeV2, or a frame to be sent exceeds that ceiling.
	ErrFrameTooLarge = errors.New("atxp: frame exceeds MaxFrameSizeV2")

	// ErrFrameTooSmall is returned when a frame is shorter than the minimum
	// envelope (nonce + GCM tag) and therefore cannot be authentic.
	ErrFrameTooSmall = errors.New("atxp: frame smaller than minimum secure envelope")

	// ErrInvalidChecksum is returned when AES-GCM authentication fails while
	// opening a frame. It means the password is wrong or the ciphertext was
	// tampered with. The two cases are intentionally indistinguishable.
	ErrInvalidChecksum = errors.New("atxp: decryption or authentication failed")

	// ErrHandshake is returned when the V2 handshake cannot be completed
	// (bad magic, unsupported version, short read).
	ErrHandshake = errors.New("atxp: handshake failed")

	// ErrWeakPassword is returned by NewV2 when the supplied password is empty.
	ErrWeakPassword = errors.New("atxp: password must be non-empty")

	// ErrReplay is returned when a received frame carries a sequence number
	// that is not strictly greater than the last accepted one, indicating a
	// replayed or reordered frame.
	ErrReplay = errors.New("atxp: out-of-order or replayed frame")

	// ErrInvalidEnvelope is returned when the decrypted plaintext does not
	// conform to the ATXP V2 internal envelope layout.
	ErrInvalidEnvelope = errors.New("atxp: malformed v2 envelope")

	// ErrInvalidKey is returned when a derived or supplied key has an
	// unexpected length for AES-256.
	ErrInvalidKey = errors.New("atxp: key must be 32 bytes for AES-256")
)
