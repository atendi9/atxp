# ATXP Protocol

A lightweight, text-framed application wire protocol designed for secure, fast, and structured communication over raw TCP or encrypted TLS transport layers. This repository provides cross-ecosystem implementations for both **Node.js (NPM)** and **Go (Golang)**.

## 📦 Ecosystem Installation

### Node.js (NPM)

```bash
npm install atxp-protocol
```

### Go (pkg.go.dev)

```sh
go get -u github.com/atendi9/atxp
```

---

## 🛠️ Usage Guide: Node.js

### 1. Initialize a Server (Node.js)

```javascript
import { Server, MT, ResponseCode, validateURLHandler } from 'atxp-protocol';

// Configure server with authentication rules
const server = new Server((username, password) => {
  return username === 'atendi9' && password === 'supersecret';
});

// Register validation middleware handlers for specific message types
server.registerHandler(MT.URL, validateURLHandler());

// Register a custom text notification payload tracker
server.registerHandler(MT.NOTIFICATION, (msg) => {
  console.log(`[Notification Alert]: ${msg.data.toString('utf8')}`);
  return ResponseCode.OK;
});

// Start listening over a local port
await server.listen(8080);
console.log('ATXP JavaScript server running on port 8080');


```

### 2. Initialize a Client (Node.js)

```javascript
import net from 'node:net';
import { Client } from 'atxp-protocol';

const socket = net.createConnection({ port: 8080 }, async () => {
  const client = new Client(socket, 'atendi9', 'supersecret');

  // Dispatch a URL framework action string
  const code = await client.sendURL('https://atendi9.com.br');
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
)

func main() {
    // Create a TCP server with credential authorization callback checking rules
    server := atxp.NewServer(func(username, password string) bool {
        return username == "atendi9" && password == "supersecret"
    })

    // Register explicit fallback validation behaviors
    server.RegisterHandler(atxp.URL, atxp.ValidateURLHandler())

    // Register custom notification business logic tracking handlers
    server.RegisterHandler(atxp.NOTIFICATION, func(msg *atxp.Message) atxp.ResponseCode {
        fmt.Printf("[Go Server] Received alert: %s\n", string(msg.Data.Get()))
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

    // Transmit structures over the stream wire channel
    status, err := client.SendNotification("Hello from the Go Client!")
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
[MESSAGE_TYPE]\t\t[BINARY_PAYLOAD_DATA]\t\tAuth:[USERNAME]::[PASSWORD]\n\n


```

### Enum References

| Name Value Token | Code Mapping Enum (Node.js) | Code Mapping Enum (Go) | Numeric Identifier Value | Description Parameters |
| --- | --- | --- | --- | --- |
| **URL** | `MT.URL` | `atxp.URL` | `0` | Resource target mapping indicator URLs. |
| **DOCUMENT** | `MT.DOCUMENT` | `atxp.DOCUMENT` | `1` | Binary data buffers payloads or structural objects. |
| **NOTIFICATION** | `MT.NOTIFICATION` | `atxp.NOTIFICATION` | `2` | Plain text alert descriptors or operational updates. |

---

## 📜 License

Distributed under the terms of the open-source **MIT License**.