package atxp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/atendi9/box"
	"github.com/atendi9/capivara/assert"
)

// mockSecureConn is an in-memory SecureConn for transport unit tests. When
// readBuf and writeBuf point at the same buffer it behaves as a sequential
// write-then-read loopback.
type mockSecureConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	readErr  error
	writeErr error
	closed   bool
}

func newLoopback() *mockSecureConn {
	buf := &bytes.Buffer{}
	return &mockSecureConn{readBuf: buf, writeBuf: buf}
}

func (m *mockSecureConn) Read(p []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	return m.readBuf.Read(p)
}

func (m *mockSecureConn) Write(p []byte) (int, error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return m.writeBuf.Write(p)
}

func (m *mockSecureConn) Close() error                      { m.closed = true; return nil }
func (m *mockSecureConn) SetReadDeadline(t time.Time) error { return nil }
func (m *mockSecureConn) SetWriteDeadline(t time.Time) error { return nil }

// trickyPayload contains every V1 delimiter plus NUL bytes and a PDF header to
// prove the V2 envelope is fully binary-safe.
var trickyPayload = []byte("URL\t\tx\t\tAuth:user::pass\n\n\x00 %PDF-1.7 \xff\xfe")

// TestNewV2 validates construction and password enforcement.
func TestNewV2(t *testing.T) {
	t.Run("rejects empty password", func(t *testing.T) {
		_, err := NewV2("")
		assert.ErrorIs(t, err, ErrWeakPassword)
	})

	t.Run("applies options", func(t *testing.T) {
		v, err := NewV2("pw", WithIterations(7), WithHandshakeTimeout(5*time.Second))
		assert.NoError(t, err)
		assert.Equal(t, 7, v.iterations)
		assert.Equal(t, 5*time.Second, v.timeout)
	})

	t.Run("ignores invalid option values", func(t *testing.T) {
		v, _ := NewV2("pw", WithIterations(-1), WithHandshakeTimeout(-1), WithMaxFrameSize(0))
		assert.Equal(t, DefaultKDFIterations, v.iterations)
		assert.Equal(t, DefaultIOTimeout, v.timeout)
		assert.Equal(t, MaxFrameSizeV2, v.maxFrameSize)
	})

	t.Run("configures a larger frame cap", func(t *testing.T) {
		v, _ := NewV2("pw", WithMaxFrameSize(64<<20))
		assert.Equal(t, 64<<20, v.maxFrameSize)
	})

	t.Run("rejects a frame cap below the minimum", func(t *testing.T) {
		v, _ := NewV2("pw", WithMaxFrameSize(MinFrameSizeV2-1))
		assert.Equal(t, MaxFrameSizeV2, v.maxFrameSize)
	})
}

// TestConfigurableFrameCap validates that the configured cap governs both the
// send guard and the receive guard.
func TestConfigurableFrameCap(t *testing.T) {
	c := newTestCipher(t, "pw", bytes.Repeat([]byte{0x0B}, SaltSize))
	// A payload that exceeds the default cap but fits a raised one.
	big := bytes.Repeat([]byte{0x7A}, MaxFrameSizeV2+1)
	msg := &Message{Type: DOCUMENT, Data: box.NewSome(big), Auth: Auth{Username: "u"}, Filename: "big.bin"}

	t.Run("default cap rejects oversized send", func(t *testing.T) {
		_, err := sendMessageFrame(newLoopback(), c, msg, 1, MaxFrameSizeV2)
		assert.ErrorIs(t, err, ErrFrameTooLarge)
	})

	t.Run("raised cap accepts oversized round trip", func(t *testing.T) {
		const raised = MaxFrameSizeV2 * 2
		conn := newLoopback()
		n, err := sendMessageFrame(conn, c, msg, 1, raised)
		assert.NoError(t, err)
		assert.True(t, n > MaxFrameSizeV2)

		got, seq, err := receiveMessageFrame(conn, c, raised)
		assert.NoError(t, err)
		assert.Equal(t, uint64(1), seq)
		assert.Equal(t, len(big), len(got.Data.Get()))
	})

	t.Run("receiver with smaller cap rejects a frame the sender allowed", func(t *testing.T) {
		conn := newLoopback()
		_, err := sendMessageFrame(conn, c, msg, 1, MaxFrameSizeV2*2)
		assert.NoError(t, err)

		_, _, err = receiveMessageFrame(conn, c, MaxFrameSizeV2)
		assert.ErrorIs(t, err, ErrFrameTooLarge)
	})
}

// TestSerializeDeserializeV2 validates the binary-safe message envelope.
func TestSerializeDeserializeV2(t *testing.T) {
	t.Run("round trip with tricky binary payload", func(t *testing.T) {
		msg := &Message{
			Type:     DOCUMENT,
			Data:     box.NewSome(trickyPayload),
			Auth:     Auth{Username: "gopher"},
			Filename: "annual::report\t.pdf",
		}
		pt, err := SerializeV2(msg, 42)
		assert.NoError(t, err)

		var out Message
		seq, err := DeserializeV2(pt, &out)
		assert.NoError(t, err)
		assert.Equal(t, uint64(42), seq)
		assert.Equal(t, DOCUMENT, out.Type)
		assert.Equal(t, "gopher", out.Auth.Username)
		assert.Equal(t, "annual::report\t.pdf", out.Filename)
		assert.Equal(t, string(trickyPayload), string(out.Data.Get()))
	})

	t.Run("round trip with custom message type and empty payload", func(t *testing.T) {
		const custom MT = 7777
		msg := &Message{Type: custom, Data: box.NewSome([]byte{}), Auth: Auth{Username: "u"}}
		pt, err := SerializeV2(msg, 1)
		assert.NoError(t, err)

		var out Message
		_, err = DeserializeV2(pt, &out)
		assert.NoError(t, err)
		assert.Equal(t, custom, out.Type)
		assert.Equal(t, 0, len(out.Data.Get()))
	})

	t.Run("nil message rejected on serialize", func(t *testing.T) {
		_, err := SerializeV2(nil, 1)
		assert.ErrorIs(t, err, ErrInvalidFormat)
	})

	t.Run("nil target rejected on deserialize", func(t *testing.T) {
		_, err := DeserializeV2([]byte{kindMessage}, nil)
		assert.ErrorIs(t, err, ErrInvalidFormat)
	})

	t.Run("malformed envelopes rejected", func(t *testing.T) {
		var out Message
		cases := [][]byte{
			{},                       // empty
			{kindResponse},           // wrong kind
			{kindMessage},            // missing seq
			append([]byte{kindMessage}, make([]byte, 8)...), // missing mtCode
		}
		for _, c := range cases {
			_, err := DeserializeV2(c, &out)
			assert.ErrorIs(t, err, ErrInvalidEnvelope)
		}
	})

	t.Run("trailing bytes rejected", func(t *testing.T) {
		msg := &Message{Type: URL, Data: box.NewSome([]byte("x")), Auth: Auth{Username: "u"}}
		pt, _ := SerializeV2(msg, 1)
		var out Message
		_, err := DeserializeV2(append(pt, 0x00), &out)
		assert.ErrorIs(t, err, ErrInvalidEnvelope)
	})

	t.Run("truncated field length rejected", func(t *testing.T) {
		// kind + seq + mtCode + a payload length claiming 99 bytes but none follow.
		buf := []byte{kindMessage}
		buf = binary.BigEndian.AppendUint64(buf, 1)
		buf = binary.BigEndian.AppendUint32(buf, uint32(URL))
		buf = binary.BigEndian.AppendUint32(buf, 99)
		var out Message
		_, err := DeserializeV2(buf, &out)
		assert.ErrorIs(t, err, ErrInvalidEnvelope)
	})
}

// TestResponseEnvelope validates the response plaintext encoding.
func TestResponseEnvelope(t *testing.T) {
	pt := serializeResponseV2(UNAUTHORIZED, 9)
	code, seq, err := deserializeResponseV2(pt)
	assert.NoError(t, err)
	assert.Equal(t, UNAUTHORIZED, code)
	assert.Equal(t, uint64(9), seq)

	_, _, err = deserializeResponseV2([]byte{kindMessage})
	assert.ErrorIs(t, err, ErrInvalidEnvelope)

	_, _, err = deserializeResponseV2([]byte{kindResponse})
	assert.ErrorIs(t, err, ErrInvalidEnvelope)
}

// TestSendReceiveV2 validates the full seal/frame/open/decode transport path.
func TestSendReceiveV2(t *testing.T) {
	c := newTestCipher(t, "pw", bytes.Repeat([]byte{0x07}, SaltSize))
	conn := newLoopback()

	msg := &Message{Type: DOCUMENT, Data: box.NewSome(trickyPayload), Auth: Auth{Username: "u"}, Filename: "f.pdf"}
	n, err := SendV2(conn, c, msg, 5)
	assert.NoError(t, err)
	assert.True(t, n > 0)

	got, seq, err := ReceiveV2(conn, c)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5), seq)
	assert.Equal(t, string(trickyPayload), string(got.Data.Get()))
	assert.Equal(t, "f.pdf", got.Filename)
}

// TestSendReceiveResponseV2 validates the response transport path.
func TestSendReceiveResponseV2(t *testing.T) {
	c := newTestCipher(t, "pw", bytes.Repeat([]byte{0x08}, SaltSize))
	conn := newLoopback()

	assert.NoError(t, SendResponseV2(conn, c, OK, 1))
	code, seq, err := ReceiveResponseV2(conn, c)
	assert.NoError(t, err)
	assert.Equal(t, OK, code)
	assert.Equal(t, uint64(1), seq)
}

// TestSendV2Errors covers serialize and write failure paths.
func TestSendV2Errors(t *testing.T) {
	c := newTestCipher(t, "pw", bytes.Repeat([]byte{0x09}, SaltSize))

	t.Run("nil message", func(t *testing.T) {
		_, err := SendV2(newLoopback(), c, nil, 1)
		assert.ErrorIs(t, err, ErrInvalidFormat)
	})

	t.Run("write failure bubbles up", func(t *testing.T) {
		conn := &mockSecureConn{readBuf: &bytes.Buffer{}, writeBuf: &bytes.Buffer{}, writeErr: errors.New("broken pipe")}
		msg := &Message{Type: URL, Data: box.NewSome([]byte("x")), Auth: Auth{Username: "u"}}
		_, err := SendV2(conn, c, msg, 1)
		assert.Error(t, err)
	})
}

// TestReceiveV2Errors covers frame size and truncation guards.
func TestReceiveV2Errors(t *testing.T) {
	c := newTestCipher(t, "pw", bytes.Repeat([]byte{0x0A}, SaltSize))

	t.Run("frame too large", func(t *testing.T) {
		buf := &bytes.Buffer{}
		var lp [LengthPrefixSize]byte
		binary.BigEndian.PutUint32(lp[:], MaxFrameSizeV2+1)
		buf.Write(lp[:])
		conn := &mockSecureConn{readBuf: buf, writeBuf: &bytes.Buffer{}}
		_, _, err := ReceiveV2(conn, c)
		assert.ErrorIs(t, err, ErrFrameTooLarge)
	})

	t.Run("frame too small", func(t *testing.T) {
		buf := &bytes.Buffer{}
		var lp [LengthPrefixSize]byte
		binary.BigEndian.PutUint32(lp[:], NonceSize+GCMTagSize-1)
		buf.Write(lp[:])
		conn := &mockSecureConn{readBuf: buf, writeBuf: &bytes.Buffer{}}
		_, _, err := ReceiveV2(conn, c)
		assert.ErrorIs(t, err, ErrFrameTooSmall)
	})

	t.Run("truncated body", func(t *testing.T) {
		buf := &bytes.Buffer{}
		var lp [LengthPrefixSize]byte
		binary.BigEndian.PutUint32(lp[:], 100)
		buf.Write(lp[:])
		buf.Write(make([]byte, 10))
		conn := &mockSecureConn{readBuf: buf, writeBuf: &bytes.Buffer{}}
		_, _, err := ReceiveV2(conn, c)
		assert.Error(t, err)
	})

	t.Run("read error bubbles up", func(t *testing.T) {
		conn := &mockSecureConn{readBuf: &bytes.Buffer{}, writeBuf: &bytes.Buffer{}, readErr: errors.New("reset")}
		_, _, err := ReceiveV2(conn, c)
		assert.Error(t, err)
	})
}

// TestHandshake validates the end-to-end key agreement over a real pipe.
func TestHandshake(t *testing.T) {
	v, err := NewV2("shared-secret", WithIterations(1))
	assert.NoError(t, err)

	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	type result struct {
		c   Cipher
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := v.ServerHandshake(srv)
		ch <- result{c, err}
	}()

	clientCipher, err := v.ClientHandshake(cli)
	assert.NoError(t, err)

	sr := <-ch
	assert.NoError(t, sr.err)

	// Keys derived independently must interoperate.
	sealed, err := sr.c.Seal([]byte("interop"))
	assert.NoError(t, err)
	opened, err := clientCipher.Open(sealed)
	assert.NoError(t, err)
	assert.Equal(t, "interop", string(opened))
}

// TestClientHandshakeErrors covers malformed handshake headers.
func TestClientHandshakeErrors(t *testing.T) {
	v, _ := NewV2("pw", WithIterations(1))

	t.Run("bad magic", func(t *testing.T) {
		hdr := make([]byte, handshakeHeaderSize)
		copy(hdr, "WRONG!")
		conn := &mockSecureConn{readBuf: bytes.NewBuffer(hdr), writeBuf: &bytes.Buffer{}}
		_, err := v.ClientHandshake(conn)
		assert.ErrorIs(t, err, ErrHandshake)
	})

	t.Run("unsupported version", func(t *testing.T) {
		hdr := make([]byte, 0, handshakeHeaderSize)
		hdr = append(hdr, HandshakeMagic...)
		hdr = append(hdr, 0xFF) // wrong version
		hdr = append(hdr, make([]byte, SaltSize)...)
		conn := &mockSecureConn{readBuf: bytes.NewBuffer(hdr), writeBuf: &bytes.Buffer{}}
		_, err := v.ClientHandshake(conn)
		assert.ErrorIs(t, err, ErrHandshake)
	})

	t.Run("short read", func(t *testing.T) {
		conn := &mockSecureConn{readBuf: bytes.NewBuffer([]byte("AT")), writeBuf: &bytes.Buffer{}}
		_, err := v.ClientHandshake(conn)
		assert.ErrorIs(t, err, ErrHandshake)
	})
}

// TestServerHandshakeWriteError ensures a write failure surfaces ErrHandshake.
func TestServerHandshakeWriteError(t *testing.T) {
	v, _ := NewV2("pw", WithIterations(1))
	conn := &mockSecureConn{readBuf: &bytes.Buffer{}, writeBuf: &bytes.Buffer{}, writeErr: io.ErrClosedPipe}
	_, err := v.ServerHandshake(conn)
	assert.ErrorIs(t, err, ErrHandshake)
}
