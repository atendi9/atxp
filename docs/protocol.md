# ATXP Protocol Specification

ATXP (Atendi9 Transmission Exchange Protocol) has two on-the-wire versions.

- **V1** — legacy, text-framed, plaintext. Kept for backward compatibility.
- **V2** — secure, binary-framed, encrypted. Recommended for all new use.

---

## V1 (legacy)

A single frame is a UTF-8 string:

```text
[MESSAGE_TYPE]\t\t[BINARY_PAYLOAD_DATA]\t\tAuth:[USERNAME]::[PASSWORD]::[FILENAME]\n\n
```

> ⚠️ **Limitations.** Credentials travel in cleartext, nothing is encrypted,
> and the `\t\t` / `\n\n` / `::` delimiters collide with arbitrary binary
> payloads (e.g. PDFs), corrupting framing. Use V2 instead.

---

## V2 (secure)

V2 encrypts every frame with **AES-256-GCM** under a key derived from a shared
password with **PBKDF2-HMAC-SHA256**. The password is never transmitted — the
GCM authentication tag proves possession. Framing is a length-prefixed binary
envelope, so any byte sequence (including PDFs) is carried losslessly.

### 1. Handshake (per connection, server-initiated)

The server writes a 22-byte header immediately on accept:

```text
"ATXP2" (5 bytes magic) | version (1 byte = 0x02) | salt (16 random bytes)
```

Both peers then derive the session key, once:

```text
K = PBKDF2-HMAC-SHA256(password, salt, iterations = 600000, dkLen = 32)
```

The salt is not secret. Authentication is implicit: if a peer's frames open
(valid GCM tag), it holds the shared password.

### 2. Encrypted frame (both directions)

```text
length (4 bytes, big-endian uint32) | nonce (12 bytes) | ciphertext+tag
```

- `length = 12 + len(plaintext) + 16`.
- A reader validates `28 ≤ length ≤ cap` before allocating, reads exactly
  `length` bytes, then opens with AES-256-GCM. The cap defaults to 16 MiB
  (`MaxFrameSizeV2`) and is configurable per endpoint via `WithMaxFrameSize`
  (Go) / `{ maxFrameSize }` (JS). A sender's cap must not exceed the
  receiver's, or large frames are rejected with `ErrFrameTooLarge`.
- A failed open yields `ErrInvalidChecksum` (wrong password or tampering — the
  two are intentionally indistinguishable).

### 3. Inner plaintext envelope (binary-safe)

```text
kind (1 byte)             # 0x01 = Message, 0x02 = Response
seq  (8 bytes, BE uint64) # monotonic per connection+direction (anti-replay)

# kind == Message:
mtCode      (4 bytes, BE uint32)
payloadLen  (4 bytes, BE) | payload  (payloadLen bytes)   # arbitrary bytes
usernameLen (4 bytes, BE) | username (...)
filenameLen (4 bytes, BE) | filename (...)

# kind == Response:
code (4 bytes, BE uint32)
```

Every variable field is length-prefixed, so the payload may contain `\t`, `\n`,
`::`, NUL, spaces — anything. There is **no password field**.

### Sequence numbers (anti-replay)

Each side keeps a send counter and an expected-receive counter per connection.
A frame whose `seq` is not strictly greater than the last accepted one is
rejected (`ErrReplay`), defeating replay and reordering within a connection.

### Registrable message types

V2 message types are registrable at runtime. Built-ins:

| Name | Code | Description |
| --- | --- | --- |
| `URL` | 0 | URLs / webhook registration. |
| `DOCUMENT` | 1 | File transfer (storage servers). |
| `NOTIFICATION` | 2 | JSON / events (event-driven architectures). |

Register a custom type with `NewMT` (Go) / `newMT` (JS); codes must be unique
and fit in a `uint32`.

### Cross-language parity

Go and Node.js produce byte-identical output. The test suites pin shared
known-answer vectors:

- PBKDF2-HMAC-SHA256(`"pw"`, 16×`0x00`, 1, 32) =
  `c30e125ad616b2f56073aca70bf0c0009177eca5e2553263a1c8de8e1c63d684`
- AES-256-GCM(key 32×`0x01`, nonce 12×`0x02`, `"atxp"`) =
  `66a2b1399775301e0dd42545400842bddb19187c`
