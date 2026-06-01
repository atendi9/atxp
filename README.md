# ATXP (Atendi9 Transmission Exchange Protocol)

A lightweight, text-framed application wire protocol designed for secure, fast, and structured communication over raw TCP or encrypted TLS transport layers. This repository provides cross-ecosystem implementations for both **Node.js (NPM)** and **Go (Golang)**.

## 📦 Ecosystem Installation

### Node.js (NPM)

```bash
npm install @atendi9/atxp-protocol
```

### Go (pkg.go.dev)

```sh
go get -u github.com/atendi9/atxp
```

---

## 🛠️ Usage Guide: Node.js

### 1. Initialize a Server (Node.js)

```javascript
import { Server, MT, ResponseCode, validateURLHandler } from '@atendi9/atxp-protocol';

// Configure server with authentication rules
const server = new Server((username, password) => {
  if (username === 'atendi9' && password === 'supersecret') {
    return { authorized: true, data: new AuthData({ role: 'admin' }) };
  }
  return { authorized: false, data: new AuthData(null) };
});

// Register validation middleware handlers for specific message types
server.registerHandler(MT.URL, validateURLHandler());

// Register a document tracker that prints the incoming filename
server.registerHandler(MT.DOCUMENT, (msg) => {
  console.log(`[Document Received]: File Name: ${msg.filename || 'unknown'}, Size: ${msg.data.length} bytes`);
  return ResponseCode.OK;
});

// Start listening over a local port
await server.listen(8080);
console.log('ATXP JavaScript server running on port 8080');
```

### 2. Initialize a Client (Node.js)

```javascript
import net from 'node:net';
import { Client } from '@atendi9/atxp-protocol';

const socket = net.createConnection({ port: 8080 }, async () => {
  const client = new Client(socket, 'atendi9', 'supersecret');

  // Dispatch a Document transaction frame along with an explicit filename tracking property
  const fileBuffer = Buffer.from('pdf_binary_content_stream');
  const code = await client.sendDocument(fileBuffer, 'annual_report.pdf');
  console.log(`Server handling code returned: ${code}`);

  socket.end();
});
```

---

## 🐹 Usage Guide: Go (Golang)

### 1. Initialize a Server (Go)

```go
package main

import (
    "fmt"
    "log"
    "github.com/atendi9/atxp"
    "github.com/atendi9/box"
)

func main() {
    // Create a TCP server with credential authorization callback checking rules
    server := atxp.NewServer(func(username, password string) (bool, atxp.AuthData) {
        if username == "atendi9" && password == "supersecret" {
            return true, box.NewSome(map[string]any{"role": "admin"})
        }
        return false, box.NewNone[map[string]any]()
    })

    // Register custom document handling tracking rules that extract the sent filename
    server.RegisterHandler(atxp.DOCUMENT, func(msg *atxp.Message, authData atxp.AuthData) atxp.ResponseCode {
        fmt.Printf("[Go Server] Document received! Name: %s, Data size: %d\n", msg.Filename, len(msg.Data.Get()))
        return atxp.OK
    })

    // Bind raw socket listener configuration channels
    listener, err := atxp.CreateServer(8080)
    if err != nil {
        log.Fatalf("Failed to initialize server port binding: %v", err)
    }

    fmt.Println("ATXP Go server is successfully running and listening over port 8080...")
    if err := server.Serve(listener); err != nil {
        log.Fatalf("Server connection loop encountered failure: %v", err)
    }
}
```

### 2. Initialize a Client (Go)

```go
package main

import (
    "fmt"
    "log"
    "github.com/atendi9/atxp"
)

func main() {
    // Establish client network pipeline targets
    conn, err := atxp.ConnectClient("127.0.0.1", 8080)
    if err != nil {
        log.Fatalf("Failed to dial destination host: %v", err)
    }
    defer atxp.CloseClient(conn)

    // Wrap active stream inside an ATXP Client interface instance
    client := atxp.NewClient(conn, "atendi9", "supersecret")

    // Transmit document payload bytes with an attached tracking filename over the wire channel
    documentBytes := []byte("example data slice content")
    status, err := client.SendDocument(documentBytes, "logs.txt")
    if err != nil {
        log.Fatalf("Failed to dispatch frame over wire stream: %v", err)
    }

    fmt.Printf("Server processing validation result returned status: %v\n", status)
}

```

---

## 📑 Wire Protocol Data Specification

ATXP frames separate parameters cleanly over active TCP sequences divided using explicit control double tab-stops (`\t\t`) and trailing delimiters (`\n\n`):

```text
[MESSAGE_TYPE]\t\t[BINARY_PAYLOAD_DATA]\t\tAuth:[USERNAME]::[PASSWORD]::[FILENAME]\n\n
```

*Note: The `::[FILENAME]` parameter is optional and only sent when the message type is `DOCUMENT` and has a configured file name.*

### Enum References

| Name Value Token | Code Mapping Enum (Node.js) | Code Mapping Enum (Go) | Numeric Identifier Value | Description Parameters |
| --- | --- | --- | --- | --- |
| **URL** | `MT.URL` | `atxp.URL` | `0` | Resource target mapping indicator URLs. |
| **DOCUMENT** | `MT.DOCUMENT` | `atxp.DOCUMENT` | `1` | Binary data buffers payloads or structural objects with optional filename attribute payload fields. |
| **NOTIFICATION** | `MT.NOTIFICATION` | `atxp.NOTIFICATION` | `2` | Plain text alert descriptors or operational updates. |

---

## 📜 License

Distributed under the terms of the open-source **MIT License**.