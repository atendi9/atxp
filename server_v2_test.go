package atxp

import (
	"net"
	"testing"
	"time"

	"github.com/atendi9/box"
	"github.com/atendi9/capivara/assert"
)

// startTestServerV2 spins up a ServerV2 on an ephemeral loopback port and
// returns its address and a cleanup function. It uses 1 KDF iteration to keep
// the handshake fast in tests.
func startTestServerV2(t *testing.T, password string, authFn AuthHandlerV2, register func(*ServerV2)) string {
	t.Helper()
	srv, err := NewServerV2(password, authFn, WithIterations(1))
	assert.NoError(t, err)
	if register != nil {
		register(srv)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)

	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().String()
}

func dialV2(t *testing.T, addr, password, username string) *ClientV2 {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	assert.NoError(t, err)
	client, err := NewClientV2(conn, password, username, WithIterations(1))
	assert.NoError(t, err)
	return client
}

// TestServerV2Construction validates password enforcement at construction.
func TestServerV2Construction(t *testing.T) {
	_, err := NewServerV2("", nil)
	assert.ErrorIs(t, err, ErrWeakPassword)
}

// TestServeNilListener validates the guard against a nil listener.
func TestServeNilListener(t *testing.T) {
	srv, _ := NewServerV2("pw", nil)
	assert.Error(t, srv.Serve(nil))
}

// TestE2EEncryptedDocument is the headline test: a binary PDF-like payload
// travels encrypted end to end and round-trips intact, while the password is
// never sent.
func TestE2EEncryptedDocument(t *testing.T) {
	const password = "shared-secret"

	type doc struct {
		data []byte
		name string
	}
	got := make(chan doc, 1)

	addr := startTestServerV2(t, password, nil, func(s *ServerV2) {
		s.RegisterHandler(DOCUMENT, func(msg *Message, _ AuthData) ResponseCode {
			got <- doc{data: msg.Data.Get(), name: msg.Filename}
			return OK
		})
	})

	client := dialV2(t, addr, password, "uploader")
	defer client.Close()

	pdf := append([]byte("%PDF-1.7\n"), trickyPayload...)
	code, err := client.SendDocument(pdf, "report.pdf")
	assert.NoError(t, err)
	assert.Equal(t, OK, code)

	select {
	case d := <-got:
		assert.Equal(t, string(pdf), string(d.data))
		assert.Equal(t, "report.pdf", d.name)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not receive the document in time")
	}
}

// TestE2EMultipleFramesAndCustomType validates sequencing and a runtime-
// registered message type over one connection.
func TestE2EMultipleFramesAndCustomType(t *testing.T) {
	const password = "pw"
	const eventType MT = 5000
	NewMT(MT_V2{Name: "EVENT", Code: eventType, Description: "event-driven payload"})

	addr := startTestServerV2(t, password, nil, func(s *ServerV2) {
		s.RegisterHandler(URL, ValidateURLHandler())
		s.RegisterHandler(eventType, func(_ *Message, _ AuthData) ResponseCode { return OK })
	})

	client := dialV2(t, addr, password, "u")
	defer client.Close()

	code, err := client.SendURL("https://atendi9.com")
	assert.NoError(t, err)
	assert.Equal(t, OK, code)

	code, err = client.Send(eventType, []byte(`{"event":"ping"}`), "")
	assert.NoError(t, err)
	assert.Equal(t, OK, code)
}

// TestE2EUnauthorized validates username-based authorization.
func TestE2EUnauthorized(t *testing.T) {
	const password = "pw"
	authFn := func(username string) (bool, AuthData) {
		return username == "trusted", AuthData(box.NewNone[map[string]any]())
	}
	addr := startTestServerV2(t, password, authFn, func(s *ServerV2) {
		s.RegisterHandler(NOTIFICATION, func(_ *Message, _ AuthData) ResponseCode { return OK })
	})

	client := dialV2(t, addr, password, "intruder")
	defer client.Close()

	code, err := client.SendNotification("hello")
	assert.NoError(t, err)
	assert.Equal(t, UNAUTHORIZED, code)
}

// TestE2EUnknownType validates that an unregistered type yields ERROR but keeps
// the connection alive for subsequent frames.
func TestE2EUnknownType(t *testing.T) {
	const password = "pw"
	addr := startTestServerV2(t, password, nil, func(s *ServerV2) {
		s.RegisterHandler(URL, ValidateURLHandler())
	})

	client := dialV2(t, addr, password, "u")
	defer client.Close()

	code, err := client.SendNotification("unhandled")
	assert.NoError(t, err)
	assert.Equal(t, ERROR, code)

	// Connection remains usable for a registered type.
	code, err = client.SendURL("https://atendi9.com")
	assert.NoError(t, err)
	assert.Equal(t, OK, code)
}

// TestE2EReplayRejected validates that a frame replayed with a non-increasing
// sequence number is rejected by the server.
func TestE2EReplayRejected(t *testing.T) {
	const password = "pw"
	addr := startTestServerV2(t, password, nil, func(s *ServerV2) {
		s.RegisterHandler(URL, func(_ *Message, _ AuthData) ResponseCode { return OK })
	})

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	assert.NoError(t, err)
	defer conn.Close()

	v, _ := NewV2(password, WithIterations(1))
	cipher, err := v.ClientHandshake(conn)
	assert.NoError(t, err)

	msg := &Message{Type: URL, Data: box.NewSome([]byte("https://atendi9.com")), Auth: Auth{Username: "u"}}

	_, err = SendV2(conn, cipher, msg, 1)
	assert.NoError(t, err)
	code, _, err := ReceiveResponseV2(conn, cipher)
	assert.NoError(t, err)
	assert.Equal(t, OK, code)

	// Replay the same sequence number.
	_, err = SendV2(conn, cipher, msg, 1)
	assert.NoError(t, err)
	code, _, err = ReceiveResponseV2(conn, cipher)
	assert.NoError(t, err)
	assert.Equal(t, ERROR, code)
}

// TestE2EWrongPassword validates that a client with the wrong password cannot
// communicate: its frames fail authentication on the server.
func TestE2EWrongPassword(t *testing.T) {
	addr := startTestServerV2(t, "correct-password", nil, func(s *ServerV2) {
		s.RegisterHandler(URL, ValidateURLHandler())
	})

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	assert.NoError(t, err)
	defer conn.Close()

	// Handshake itself does not authenticate; key derivation just yields a
	// different key from the wrong password.
	client, err := NewClientV2(conn, "wrong-password", "u", WithIterations(1))
	assert.NoError(t, err)

	// The first frame cannot be opened by the server, which closes the
	// connection; the client's response read therefore fails.
	_, err = client.SendURL("https://atendi9.com")
	assert.Error(t, err)
}
