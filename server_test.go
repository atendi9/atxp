package atxp

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/atendi9/box"
	"github.com/atendi9/capivara/assert"
)

// mockListener implements the net.Listener interface for polling tests.
type mockListener struct {
	conns  chan net.Conn
	closed chan struct{}
}

func newMockListener() *mockListener {
	return &mockListener{
		conns:  make(chan net.Conn, 10),
		closed: make(chan struct{}),
	}
}

// Accept yields a mocked network connection channel payload or blocks until closed.
func (m *mockListener) Accept() (net.Conn, error) {
	select {
	case conn := <-m.conns:
		return conn, nil
	case <-m.closed:
		return nil, errors.New("listener closed")
	}
}

// Close terminates the mock listener instance lifecycle.
func (m *mockListener) Close() error {
	close(m.closed)
	return nil
}

// Addr returns a placeholder local network address descriptor.
func (m *mockListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

// mockNetConn bridges mockNetworkIO with the net.Conn interface requirements.
type mockNetConn struct {
	*mockNetworkIO
}

func (m *mockNetConn) LocalAddr() net.Addr                { return nil }
func (m *mockNetConn) RemoteAddr() net.Addr               { return nil }
func (m *mockNetConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockNetConn) SetWriteDeadline(t time.Time) error { return nil }

// TestNewServer verifies that NewServer configures an empty server with authentication callback rules.
func TestNewServer(t *testing.T) {
	authFn := func(username, password string) (bool, AuthData) {
		if username == "root" && password == "admin" {
			return true, box.NewSome(map[string]any{})
		}
		return false, box.NewNone[map[string]any]()
	}

	server := NewServer(authFn)

	assert.LengthMap(t, 0, server.handlers)
	authorized, _ := server.authFn("root", "admin")
	assert.True(t, authorized)
	authorized, _ = server.authFn("root", "wrong")
	assert.False(t, authorized)
}

// TestRegisterHandler ensures routes mapping functions persist correctly inside internal structures.
func TestRegisterHandler(t *testing.T) {
	server := NewServer(nil)
	dummyHandler := func(msg *Message, _ AuthData) ResponseCode { return OK }

	server.RegisterHandler(URL, dummyHandler)

	assert.LengthMap(t, 1, server.handlers)
}

// TestServer_Serve_NilListener ensures passing a nil listener framework yields an error wrapper.
func TestServer_Serve_NilListener(t *testing.T) {
	server := NewServer(nil)
	err := server.Serve(nil)
	assert.Error(t, err)
}

// TestServer_HandleConnection_Success validates processing structured frames and routing to handlers.
func TestServer_HandleConnection_Success(t *testing.T) {
	authFn := func(username, password string) (bool, AuthData) { return true, box.NewSome(map[string]any{}) }
	server := NewServer(authFn)

	server.RegisterHandler(URL, func(msg *Message, _ AuthData) ResponseCode {
		return OK
	})

	// Valid URL frame matching criteria
	rawFrame := "URL\t\thttps://atendi9.com\t\tAuth:user::pass\n\n"
	mockConn := &mockNetworkIO{
		readBuf:  bytes.NewBufferString(rawFrame),
		writeBuf: &bytes.Buffer{},
	}

	server.HandleConnection(mockConn)

	assert.True(t, mockConn.isClosed)
	// Response Code format write sequence matching validation metrics
	assert.Equal(t, "RESP:0\n\n", mockConn.writeBuf.String())
}

// TestServer_HandleConnection_Unauthorized checks that invalid auth returns UNAUTHORIZED status frame sequence.
func TestServer_HandleConnection_Unauthorized(t *testing.T) {
	authFn := func(username, password string) (bool, AuthData) { return false, box.NewNone[map[string]any]() }
	server := NewServer(authFn)

	rawFrame := "URL\t\thttps://atendi9.com\t\tAuth:intruder::hack\n\n"
	mockConn := &mockNetworkIO{
		readBuf:  bytes.NewBufferString(rawFrame),
		writeBuf: &bytes.Buffer{},
	}

	server.HandleConnection(mockConn)

	assert.Equal(t, "RESP:2\n\n", mockConn.writeBuf.String()) // 2 == UNAUTHORIZED
}

// TestServer_HandleConnection_NoHandler checks that missing route schemas return ERROR payload codes.
func TestServer_HandleConnection_NoHandler(t *testing.T) {
	authFn := func(username, password string) (bool, AuthData) { return true, box.NewSome(map[string]any{}) }
	server := NewServer(authFn)

	// Sending DOCUMENT framing without an explicit mapped handler definition rule set
	rawFrame := "Document\t\tsome_data\t\tAuth:user::pass\n\n"
	mockConn := &mockNetworkIO{
		readBuf:  bytes.NewBufferString(rawFrame),
		writeBuf: &bytes.Buffer{},
	}

	server.HandleConnection(mockConn)

	assert.Equal(t, "RESP:1\n\n", mockConn.writeBuf.String()) // 1 == ERROR
}

// TestServer_HandleConnection_MalformedPacket checks response framing when buffer parsing routines break down.
func TestServer_HandleConnection_MalformedPacket(t *testing.T) {
	authFn := func(username, password string) (bool, AuthData) { return false, box.NewNone[map[string]any]() }
	server := NewServer(authFn)

	rawFrame := "INVALID_FORMAT_PACKET_WITHOUT_TABS\n\n"
	mockConn := &mockNetworkIO{
		readBuf:  bytes.NewBufferString(rawFrame),
		writeBuf: &bytes.Buffer{},
	}

	server.HandleConnection(mockConn)

	assert.Equal(t, "RESP:1\n\n", mockConn.writeBuf.String()) // 1 == ERROR
}

// TestValidateURLHandler confirms URL string formatting and prefixes validations operate correctly.
func TestValidateURLHandler(t *testing.T) {
	handler := ValidateURLHandler()

	msgHTTP := &Message{Data: box.NewSome([]byte("http://localhost"))}
	assert.Equal(t, OK, handler(msgHTTP, box.NewNone[map[string]any]()))

	msgHTTPS := &Message{Data: box.NewSome([]byte("https://atendi9.com"))}
	assert.Equal(t, OK, handler(msgHTTPS, box.NewNone[map[string]any]()))

	msgInvalid := &Message{Data: box.NewSome([]byte("ftp://atendi9.com"))}
	assert.Equal(t, ERROR, handler(msgInvalid, box.NewNone[map[string]any]()))

	msgEmpty := &Message{Data: box.NewSome([]byte{})}
	assert.Equal(t, ERROR, handler(msgEmpty, box.NewNone[map[string]any]()))
}

// TestValidateDocumentHandler evaluates byte boundary criteria checking schemas.
func TestValidateDocumentHandler(t *testing.T) {
	handler := ValidateDocumentHandler(10)

	msgValid := &Message{Data: box.NewSome([]byte("12345"))}
	assert.Equal(t, OK, handler(msgValid, box.NewNone[map[string]any]()))

	msgTooLong := &Message{Data: box.NewSome([]byte("12345678901"))}
	assert.Equal(t, ERROR, handler(msgTooLong, box.NewNone[map[string]any]()))

	msgZeroLength := &Message{Data: box.NewSome([]byte(""))}
	assert.Equal(t, ERROR, handler(msgZeroLength, box.NewNone[map[string]any]()))

	msgEmpty := &Message{Data: box.NewSome([]byte{})}
	assert.Equal(t, ERROR, handler(msgEmpty, box.NewNone[map[string]any]()))
}
