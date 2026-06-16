# ATXP Security Model

This document covers the ATXP **V2** secure layer. V1 offers no
confidentiality, integrity, or authentication and must not be used on untrusted
networks.

## Goals

| Property | Mechanism |
| --- | --- |
| Confidentiality | AES-256-GCM encrypts the whole frame. |
| Integrity / tamper-evidence | GCM authentication tag (16 bytes). |
| Authentication | Implicit: only a peer holding the shared password derives the key that opens frames. |
| Secret never on the wire | The password derives the key via PBKDF2; it is never transmitted, in cleartext or otherwise. |
| Binary safety | Length-prefixed envelope — no in-band delimiters. |
| DoS resistance | Frame cap (16 MiB default, configurable via `WithMaxFrameSize` / `{ maxFrameSize }`) + bounded reads + I/O deadlines. |
| Replay resistance (intra-connection) | Strictly increasing per-connection sequence numbers. |

## Key derivation

`K = PBKDF2-HMAC-SHA256(password, salt, 600000, 32)`

- Salt is 16 random bytes from `crypto/rand` (Go) / `crypto.randomBytes` (JS),
  fresh per connection, sent in the handshake (not secret).
- The iteration count (`DefaultKDFIterations = 600000`, OWASP guidance) is
  applied **once per connection**, not per frame, bounding CPU cost.
- Both peers must agree on the iteration count (configurable via
  `WithIterations` / `{ iterations }`).

## Encryption

- AES-256-GCM with a fresh random 12-byte nonce per frame (from a CSPRNG).
  Reusing a (key, nonce) pair would break GCM; random 96-bit nonces under a
  per-connection key make collision negligible for any realistic frame count.
- Frame layout: `nonce || ciphertext || tag`. Decryption failure is reported as
  a single opaque `ErrInvalidChecksum` so wrong-password and tampering are
  indistinguishable to an attacker.

## Threat model

**In scope / mitigated**

- Passive eavesdropping — ciphertext only; payload and identity (beyond the
  username, which is itself encrypted) are not readable.
- Active tampering — any bit flip fails the GCM tag.
- Wrong-password peers — cannot open frames; the server closes the connection.
- Unbounded-memory and hung-connection DoS — frame cap and deadlines.
- Replay/reordering within a live connection — sequence numbers.

**Out of scope / caveats**

- **Forward secrecy.** A single static password-derived key per connection; a
  compromised password decrypts past captures. A future V3 could add an
  ephemeral Diffie-Hellman handshake.
- **Cross-connection replay.** Sequence numbers reset per connection; an
  attacker replaying a whole prior *connection* is not detected at this layer.
  Use application-level idempotency keys if this matters.
- **Password strength.** Security rests entirely on the shared password. Use a
  high-entropy secret; PBKDF2 slows but does not eliminate brute force.
- **Transport.** V2 may run over plain TCP (it is self-encrypting) or over TLS
  for defense in depth and server identity.

## Operational guidance

- Never log payloads, keys, salts, or derived material. Log only metadata
  (message type, size, sequence).
- Distribute the shared password out-of-band over a secure channel.
- Rotate the password periodically; rotation takes effect on new connections.
- The frame cap bounds the memory a single connection can force the peer to
  allocate. Raising it (`WithMaxFrameSize` / `{ maxFrameSize }`) to support large
  documents widens that exposure — size it to your real payloads and available
  memory, not arbitrarily high. Keep the sender's cap ≤ the receiver's.
