# ATXP (Atendi9 Transmission Exchange Protocol)

A lightweight, **encrypted** application wire protocol for fast, structured communication over raw TCP or TLS. Every frame is encrypted with AES-256-GCM under a key derived from a shared password — **the password is never transmitted**. This repository provides cross-ecosystem implementations for both **Node.js (NPM)** and **Go (Golang)** with a byte-identical wire format.

> ⚠️ **About V1.** The original ATXP was a proof of concept: it sent credentials and payloads in **cleartext** and its text delimiters (`\t\t`, `\n\n`, `::`) collided with arbitrary binary data, corrupting PDFs and other files. It is **insecure and deprecated** — this README documents only the secure **V2** protocol. The V1 symbols remain in the codebase for backward compatibility but must not be used on untrusted networks.

## 📦 Installation

### Node.js (NPM)

```bash
npm install @atendi9/atxp-protocol
```

### Go (pkg.go.dev)

```sh
go get -u github.com/atendi9/atxp
```

---

## 🔐 Why V2 is secure

| Property | Mechanism |
| --- | --- |
| **Confidentiality** | AES-256-GCM encrypts the whole frame. |
| **Integrity** | GCM authentication tag detects any tampering. |
| **Authentication** | Implicit — only a peer holding the shared password derives the key that opens frames. |
| **Secret never on the wire** | Key is derived from the password via PBKDF2-HMAC-SHA256; the password itself is never sent. |
| **Binary-safe** | Length-prefixed binary envelope carries PDFs/images losslessly. |
| **DoS resistance** | Frame cap (16 MiB default, [configurable](#-tuning-the-frame-size-cap)), bounded reads, and I/O deadlines. |
| **Replay resistance** | Strictly increasing per-connection sequence numbers. |

Full details in [`docs/protocol.md`](docs/protocol.md) and [`docs/security.md`](docs/security.md).

---

## 🛠️ Usage Guide: Node.js

### 1. Initialize a Secure Server

```javascript
import { ServerV2, MT, ResponseCode, AuthData, validateURLHandler } from '@atendi9/atxp-protocol';

// The shared password derives the encryption key. Authorization is by username
// only — possession of the password is already proven by successful decryption.
const server = new ServerV2('shared-secret', (username) => {
  if (username === 'atendi9') {
    return { authorized: true, data: new AuthData({ role: 'admin' }) };
  }
  return { authorized: false, data: new AuthData(null) };
});

server.registerHandler(MT.URL, validateURLHandler());

server.registerHandler(MT.DOCUMENT, (msg) => {
  console.log(`[Document Received]: ${msg.filename || 'unknown'}, ${msg.data.length} encrypted bytes`);
  return ResponseCode.OK;
});

const listening = await server.listen(8443);
console.log('ATXP V2 server running on port 8443');
```

### 2. Initialize a Secure Client

```javascript
import net from 'node:net';
import { newClientV2 } from '@atendi9/atxp-protocol';

const socket = net.createConnection({ port: 8443 }, async () => {
  // newClientV2 performs the encrypted handshake before resolving.
  const client = await newClientV2(socket, 'shared-secret', 'atendi9');

  // A binary PDF travels fully encrypted and arrives intact.
  const fileBuffer = Buffer.from('%PDF-1.7\n...binary content...');
  const code = await client.sendDocument(fileBuffer, 'annual_report.pdf');
  console.log(`Server returned: ${code}`);

  client.close();
});
```

---

## 🐹 Usage Guide: Go (Golang)

### 1. Initialize a Secure Server

```go
package main

import (
    "fmt"
    "log"

    "github.com/atendi9/atxp"
    "github.com/atendi9/box"
)

func main() {
    // The shared password derives the per-connection key; auth is by username.
    server, err := atxp.NewServerV2("shared-secret", func(username string) (bool, atxp.AuthData) {
        if username == "atendi9" {
            return true, box.NewSome(map[string]any{"role": "admin"})
        }
        return false, box.NewNone[map[string]any]()
    })
    if err != nil {
        log.Fatalf("Failed to create server: %v", err)
    }

    server.RegisterHandler(atxp.DOCUMENT, func(msg *atxp.Message, _ atxp.AuthData) atxp.ResponseCode {
        fmt.Printf("[Go Server] Document %q received, %d encrypted bytes\n", msg.Filename, len(msg.Data.Get()))
        return atxp.OK
    })

    listener, err := atxp.CreateServer(8443)
    if err != nil {
        log.Fatalf("Failed to bind listener: %v", err)
    }

    fmt.Println("ATXP V2 Go server listening on port 8443...")
    if err := server.Serve(listener); err != nil {
        log.Fatalf("Server loop failed: %v", err)
    }
}
```

### 2. Initialize a Secure Client

```go
package main

import (
    "fmt"
    "log"

    "github.com/atendi9/atxp"
)

func main() {
    conn, err := atxp.ConnectClient("127.0.0.1", 8443)
    if err != nil {
        log.Fatalf("Failed to dial host: %v", err)
    }

    // NewClientV2 performs the encrypted handshake on construction.
    client, err := atxp.NewClientV2(conn, "shared-secret", "atendi9")
    if err != nil {
        log.Fatalf("Handshake failed: %v", err)
    }
    defer client.Close()

    documentBytes := []byte("%PDF-1.7\n...binary content...")
    status, err := client.SendDocument(documentBytes, "report.pdf")
    if err != nil {
        log.Fatalf("Failed to send frame: %v", err)
    }

    fmt.Printf("Server returned status: %v\n", status)
}
```

---

## 🧩 Registering custom message types

V2 message types are registrable at runtime. Codes must be unique and fit in a `uint32`.

```go
atxp.NewMT(atxp.MT_V2{Name: "WEBHOOK", Code: 100, Description: "external webhook registration"}) // Go
```
```javascript
newMT({ name: 'WEBHOOK', code: 100, description: 'external webhook registration' }); // JS
```

Then send with the custom code:

```go
client.Send(100, payload, "")            // Go
```
```javascript
await client.send(100, payload, '');     // JS
```

---

## 📏 Tuning the frame size cap

Each encrypted frame is capped at **16 MiB by default** to bound memory use. Beefier servers that must transfer larger documents can raise the cap — and constrained environments can lower it. Set it on both the server and the client (a sender's cap must not exceed the receiver's, or large frames are rejected):

```go
// Go — 64 MiB cap. Values below the minimum valid frame size are ignored.
server, _ := atxp.NewServerV2("shared-secret", authFn, atxp.WithMaxFrameSize(64<<20))
client, _ := atxp.NewClientV2(conn, "shared-secret", "atendi9", atxp.WithMaxFrameSize(64<<20))
```
```javascript
// Node.js — 64 MiB cap via the options object.
const server = new ServerV2('shared-secret', authFn, { maxFrameSize: 64 * 1024 * 1024 });
const client = await newClientV2(socket, 'shared-secret', 'atendi9', { maxFrameSize: 64 * 1024 * 1024 });
```

---

## 📑 V2 Wire Protocol Specification

Each connection begins with a server-initiated handshake, after which every frame is encrypted.

**Handshake (22 bytes, server → client):**

```text
"ATXP2" (5B magic) | version (1B = 0x02) | salt (16B random)
```

Both peers derive `K = PBKDF2-HMAC-SHA256(password, salt, 600000, 32)`.

**Encrypted frame (both directions):**

```text
length (4B BE uint32) | nonce (12B) | AES-256-GCM(ciphertext + tag)
```

**Inner plaintext envelope (length-prefixed, binary-safe):**

```text
kind (1B)            # 0x01 = Message, 0x02 = Response
seq  (8B BE uint64)  # monotonic per connection (anti-replay)
mtCode      (4B BE) | payloadLen (4B) | payload | userLen (4B) | username | fnameLen (4B) | filename
```

There is **no password field** anywhere on the wire. See [`docs/protocol.md`](docs/protocol.md) for the complete specification, including cross-language known-answer test vectors.

### Built-in Message Types

| Name | `MT.X` (Node.js) | `atxp.X` (Go) | Code | Description |
| --- | --- | --- | --- | --- |
| **URL** | `MT.URL` | `atxp.URL` | `0` | URLs / webhook registration. |
| **DOCUMENT** | `MT.DOCUMENT` | `atxp.DOCUMENT` | `1` | Binary file transfer with optional filename. |
| **NOTIFICATION** | `MT.NOTIFICATION` | `atxp.NOTIFICATION` | `2` | JSON or events for event-driven architectures. |

---

## 📜 License

Distributed under the terms of the open-source **MIT License**.
