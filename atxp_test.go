package atxp

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/atendi9/box"
	"github.com/atendi9/capivara/assert"
)

// mockNetworkIO implements the NetworkIO interface for standalone stream isolation testing.
type mockNetworkIO struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	writeErr error
	readErr error
	isClosed bool
}

func (m *mockNetworkIO) Read(p []byte) (n int, err error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	return m.readBuf.Read(p)
}

func (m *mockNetworkIO) Write(p []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return m.writeBuf.Write(p)
}

func (m *mockNetworkIO) Close() error {
	m.isClosed = true
	return nil
}

// TestTypeToString validates conversion from message type enum to string representation.
func TestTypeToString(t *testing.T) {
	assert.Equal(t, "URL", TypeToString(URL))
	assert.Equal(t, "Document", TypeToString(DOCUMENT))
	assert.Equal(t, "Notification", TypeToString(NOTIFICATION))
	assert.Equal(t, "UNKNOWN", TypeToString(MT(99)))
}

// TestStringToType validates parsing from string back to message type enum tokens.
func TestStringToType(t *testing.T) {
	assert.Equal(t, URL, StringToType("URL"))
	assert.Equal(t, DOCUMENT, StringToType("Document"))
	assert.Equal(t, NOTIFICATION, StringToType("Notification"))
	assert.Equal(t, MT(-1), StringToType("INVALID"))
}

// TestSerialize verifies the correct wire framing and formatting outputs of messages.
func TestSerialize(t *testing.T) {
	t.Run("success serialization with data", func(t *testing.T) {
		msg := &Message{
			Type: URL,
			Data: box.NewSome([]byte("https://atendi9.com")),
			Auth: Auth{Username: "admin", Password: "pwd"},
		}

		result, err := Serialize(msg)
		assert.NoError(t, err)

		expected := "URL\t\thttps://atendi9.com\t\tAuth:admin::pwd\n\n"
		assert.Equal(t, expected, string(result))
	})

	t.Run("success serialization with empty data", func(t *testing.T) {
		msg := &Message{
			Type: NOTIFICATION,
			Data: box.NewSome([]byte{}),
			Auth: Auth{Username: "user", Password: "123"},
		}

		result, err := Serialize(msg)
		assert.NoError(t, err)

		expected := "Notification\t\t\t\tAuth:user::123\n\n"
		assert.Equal(t, expected, string(result))
	})

	t.Run("nil message error handling", func(t *testing.T) {
		result, err := Serialize(nil)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidFormat, err)
		assert.True(t, result == nil)
	})
}

// TestDeserialize validates parsing compliance and robustness against malformed data blocks.
func TestDeserialize(t *testing.T) {
	t.Run("success parsing valid packet", func(t *testing.T) {
		buffer := "Document\t\tsome-doc-payload\t\tAuth:gopher::secret::doc.txt\n\n"
		var msg Message

		err := Deserialize(buffer, &msg)
		assert.NoError(t, err)
		assert.Equal(t, DOCUMENT, msg.Type)
		assert.Equal(t, "gopher", msg.Auth.Username)
		assert.Equal(t, "secret", msg.Auth.Password)
		assert.Equal(t, "some-doc-payload", string(msg.Data.Get()))
		assert.Equal(t, "doc.txt", msg.Filename)
	})

	t.Run("error parsing nil target reference", func(t *testing.T) {
		err := Deserialize("URL\t\t\t\tAuth:a::b\n\n", nil)
		assert.Error(t, err)
	})

	t.Run("error parsing empty buffer stream", func(t *testing.T) {
		var msg Message
		err := Deserialize("", &msg)
		assert.Error(t, err)
	})

	t.Run("error parsing missing protocol tab separator", func(t *testing.T) {
		var msg Message
		err := Deserialize("URL payload Auth:a::b\n\n", &msg)
		assert.Error(t, err)
	})

	t.Run("error parsing missing protocol authorization header token", func(t *testing.T) {
		var msg Message
		err := Deserialize("URL\t\tpayload\t\tWrongHeader:a::b\n\n", &msg)
		assert.Error(t, err)
	})

	t.Run("error parsing missing trailing delimiter newlines", func(t *testing.T) {
		var msg Message
		err := Deserialize("URL\t\tpayload\t\tAuth:a::b", &msg)
		assert.Error(t, err)
	})

	t.Run("error parsing missing authentication payload separator tokens", func(t *testing.T) {
		var msg Message
		err := Deserialize("URL\t\tpayload\t\tAuth:asecret\n\n", &msg)
		assert.Error(t, err)
	})
}

// TestCreateServer validates standard TCP socket initialization.
func TestCreateServer(t *testing.T) {
	listener, err := CreateServer(0) // 0 allocates an ephemeral port dynamically
	assert.NoError(t, err)
	assert.True(t, listener != nil)

	err = listener.Close()
	assert.NoError(t, err)
}

// TestCreateTLSServer verifies configuration enforcement rules for secure contexts.
func TestCreateTLSServer(t *testing.T) {
	t.Run("fails when tls configuration context is nil", func(t *testing.T) {
		listener, err := CreateTLSServer(0, nil)
		assert.Error(t, err)
		assert.True(t, listener == nil)
	})
}

// TestConnectClientAndCloseClient orchestrates end-to-end standard stream connections.
func TestConnectClientAndCloseClient(t *testing.T) {
	listener, err := CreateServer(0)
	assert.NoError(t, err)
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)

	// Using mock synchronization variables for integration handling
	done := make(chan bool, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
		done <- true
	}()

	clientConn, err := ConnectClient("localhost", addr.Port)
	assert.NoError(t, err)
	assert.True(t, clientConn != nil)

	err = CloseClient(clientConn)
	assert.NoError(t, err)

	err = CloseClient(nil)
	assert.NoError(t, err)

	<-done
}

// TestConnectTLSClient verifies structural constraints of standard TLS outbound pathways.
func TestConnectTLSClient(t *testing.T) {
	t.Run("fails connection gracefully with invalid configuration context values", func(t *testing.T) {
		config := &tls.Config{InsecureSkipVerify: true}
		_, err := ConnectTLSClient("localhost", 9999, config)
		assert.Error(t, err)
	})
}

// TestReceive verifies protocol parsing stream loop termination bounds.
func TestReceive(t *testing.T) {
	t.Run("reads sequential frames until matching tail break sequence tokens", func(t *testing.T) {
		mock := &mockNetworkIO{
			readBuf:  bytes.NewBufferString("Notification\t\thi\t\tAuth:u::p\n\nremainder payload"),
			writeBuf: &bytes.Buffer{},
		}

		result, err := Receive(mock)
		assert.NoError(t, err)
		assert.Equal(t, "Notification\t\thi\t\tAuth:u::p\n\n", result)
	})

	t.Run("handles io end of file scenarios gracefully without error output flags", func(t *testing.T) {
		mock := &mockNetworkIO{
			readBuf:  bytes.NewBufferString("FragmentedDataWithoutTails"),
			writeBuf: &bytes.Buffer{},
		}

		result, err := Receive(mock)
		assert.NoError(t, err)
		assert.Equal(t, "FragmentedDataWithoutTails", result)
	})

	t.Run("bubbles up connection error conditions directly from source reader hooks", func(t *testing.T) {
		mock := &mockErrNetworkIO{err: errors.New("abrupt pipe failure")}
		result, err := Receive(mock)
		assert.Error(t, err)
		assert.Equal(t, "", result)
	})
}

// TestSend validates serialization pipe passing to active network streams.
func TestSend(t *testing.T) {
	t.Run("success formatting data and dispatching stream pipeline output bytes", func(t *testing.T) {
		mock := &mockNetworkIO{
			readBuf:  &bytes.Buffer{},
			writeBuf: &bytes.Buffer{},
		}
		msg := &Message{
			Type: URL,
			Data: box.NewSome([]byte("data")),
			Auth: Auth{Username: "a", Password: "b"},
		}

		n, err := Send(mock, msg)
		assert.NoError(t, err)
		assert.True(t, n > 0)
		assert.Equal(t, "URL\t\tdata\t\tAuth:a::b\n\n", mock.writeBuf.String())
	})

	t.Run("fails when message validation parameters error during serialization step", func(t *testing.T) {
		mock := &mockNetworkIO{
			readBuf:  &bytes.Buffer{},
			writeBuf: &bytes.Buffer{},
		}
		n, err := Send(mock, nil)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})
}

// TestSendResponse evaluates code signaling behavior across structured wire formats.
func TestSendResponse(t *testing.T) {
	t.Run("success dispatching valid response envelope wrappers", func(t *testing.T) {
		mock := &mockNetworkIO{
			readBuf:  &bytes.Buffer{},
			writeBuf: &bytes.Buffer{},
		}

		code, err := SendResponse(mock, OK)
		assert.NoError(t, err)
		assert.Equal(t, "RESP:0\n\n", mock.writeBuf.String())
		assert.Equal(t, ResponseCode(len("RESP:0\n\n")), code)
	})

	t.Run("returns generic system error indicator tokens on writer faults", func(t *testing.T) {
		mock := &mockErrNetworkIO{err: errors.New("disconnected endpoint connection")}
		code, err := SendResponse(mock, OK)
		assert.Error(t, err)
		assert.Equal(t, ERROR, code)
	})
}

// TestReceiveResponse processes acknowledgment token states cleanly.
func TestReceiveResponse(t *testing.T) {
	t.Run("success translating standard clean response message headers", func(t *testing.T) {
		mock := &mockNetworkIO{
			readBuf:  bytes.NewBufferString("RESP:2\n\n"),
			writeBuf: &bytes.Buffer{},
		}

		code, err := ReceiveResponse(mock)
		assert.NoError(t, err)
		assert.Equal(t, UNAUTHORIZED, code)
	})

	t.Run("returns error indicators if data stream contents are empty strings", func(t *testing.T) {
		mock := &mockNetworkIO{
			readBuf:  bytes.NewBufferString(""),
			writeBuf: &bytes.Buffer{},
		}

		code, err := ReceiveResponse(mock)
		assert.Error(t, err)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, ERROR, code)
	})

	t.Run("returns invalid format indicators on reading garbage payloads", func(t *testing.T) {
		mock := &mockNetworkIO{
			readBuf:  bytes.NewBufferString("MALFORMED_RESP_STRING\n\n"),
			writeBuf: &bytes.Buffer{},
		}

		code, err := ReceiveResponse(mock)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidFormat, err)
		assert.Equal(t, ERROR, code)
	})

	t.Run("handles reader errors gracefully failing upstream safely", func(t *testing.T) {
		mock := &mockErrNetworkIO{err: errors.New("hardware timeout loop interruption")}
		code, err := ReceiveResponse(mock)
		assert.Error(t, err)
		assert.Equal(t, ERROR, code)
	})
}

// mockErrNetworkIO provides deterministic stream faults to simulate underlying transport errors.
type mockErrNetworkIO struct {
	err error
}

func (m *mockErrNetworkIO) Read(p []byte) (n int, err error) {
	return 0, m.err
}

func (m *mockErrNetworkIO) Write(p []byte) (n int, err error) {
	return 0, m.err
}

func (m *mockErrNetworkIO) Close() error {
	return m.err
}