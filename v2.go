// Package atxp implements the ATXP (Atendi9 Transmission Exchange Protocol) wire protocol framing and transport layer.
//   - Copyright (c) 2026 Atendi9
//
// # ATXP V2 secure layer
//
// V2 is an additive, backward-incompatible-on-the-wire successor to V1 that
// fixes V1's security and robustness flaws:
//
//   - The whole frame is encrypted with AES-256-GCM under a key derived from a
//     shared password via PBKDF2-HMAC-SHA256. The password is never
//     transmitted; possession is proven implicitly by the GCM authentication
//     tag.
//   - Frames use a length-prefixed binary envelope, so arbitrary binary
//     payloads (PDFs, images, anything) are carried losslessly and no payload
//     byte can collide with a delimiter.
//   - Reads are bounded by MaxFrameSizeV2 and every I/O operation has a
//     deadline, preventing unbounded-memory and hung-connection denial of
//     service.
//   - A monotonic per-connection sequence number defends against replay and
//     reordering.
package atxp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/atendi9/box"
)

// Protocol-level constants for ATXP V2. None are magic numbers.
const (
	// ProtocolVersionV2 is the version byte sent in the handshake header.
	ProtocolVersionV2 = 2
	// HandshakeMagic prefixes the handshake header so peers can detect a
	// non-ATXP-V2 stream early.
	HandshakeMagic = "ATXP2"
	// LengthPrefixSize is the size in bytes of the big-endian frame length.
	LengthPrefixSize = 4
	// MaxFrameSizeV2 is the default ceiling on a single encrypted frame
	// (16 MiB). It can be raised or lowered per endpoint with
	// [WithMaxFrameSize] — useful for beefier servers that must accept larger
	// documents.
	MaxFrameSizeV2 = 1 << 24
	// MinFrameSizeV2 is the smallest a valid encrypted frame can be: a 12-byte
	// nonce plus a 16-byte GCM tag. A configured cap below this is rejected.
	MinFrameSizeV2 = NonceSize + GCMTagSize
	// DefaultIOTimeout bounds every frame read/write and handshake step.
	DefaultIOTimeout = 30 * time.Second

	// handshakeHeaderSize is magic(5) + version(1) + salt(16) = 22 bytes.
	handshakeHeaderSize = len(HandshakeMagic) + 1 + SaltSize

	// Inner envelope kinds.
	kindMessage  byte = 0x01
	kindResponse byte = 0x02
)

// SecureConn is the transport contract required by the V2 layer. The standard
// library [net.Conn] satisfies it. Declaring deadline methods in the interface
// keeps every I/O operation bounded and keeps the layer testable with mocks.
type SecureConn interface {
	io.ReadWriteCloser
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// V2 holds the shared secret and key-derivation parameters for an ATXP V2
// endpoint. It is safe for concurrent use; the derived per-connection [Cipher]
// is what carries connection state.
type V2 struct {
	password     string
	iterations   int
	timeout      time.Duration
	maxFrameSize int
}

// OptionV2 configures a [V2] instance.
type OptionV2 func(*V2)

// WithIterations overrides the PBKDF2 iteration count. Values <= 0 are ignored.
// Both peers must use the same value to derive matching keys.
func WithIterations(n int) OptionV2 {
	return func(v *V2) {
		if n > 0 {
			v.iterations = n
		}
	}
}

// WithHandshakeTimeout overrides the deadline applied to handshake I/O.
func WithHandshakeTimeout(d time.Duration) OptionV2 {
	return func(v *V2) {
		if d > 0 {
			v.timeout = d
		}
	}
}

// WithMaxFrameSize overrides the maximum encrypted frame size accepted and
// emitted by [ClientV2] and [ServerV2] built from this endpoint. Raise it for
// servers that must transfer large documents, or lower it to tighten the
// denial-of-service surface. Values below [MinFrameSizeV2] are ignored, keeping
// the default [MaxFrameSizeV2]. Peers should agree on a compatible cap: a
// sender's cap must not exceed the receiver's, or large frames are rejected.
func WithMaxFrameSize(n int) OptionV2 {
	return func(v *V2) {
		if n >= MinFrameSizeV2 {
			v.maxFrameSize = n
		}
	}
}

// NewV2 creates a V2 endpoint from a shared password. It returns
// [ErrWeakPassword] when the password is empty.
func NewV2(password string, opts ...OptionV2) (*V2, error) {
	if password == "" {
		return nil, ErrWeakPassword
	}
	v := &V2{
		password:     password,
		iterations:   DefaultKDFIterations,
		timeout:      DefaultIOTimeout,
		maxFrameSize: MaxFrameSizeV2,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v, nil
}

// ServerHandshake performs the server side of the V2 handshake: it generates a
// random salt, transmits the handshake header, and returns the session
// [Cipher]. The salt is not secret.
func (v *V2) ServerHandshake(conn SecureConn) (Cipher, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("atxp.ServerHandshake: salt: %w", err)
	}

	header := make([]byte, 0, handshakeHeaderSize)
	header = append(header, HandshakeMagic...)
	header = append(header, ProtocolVersionV2)
	header = append(header, salt...)

	if err := conn.SetWriteDeadline(time.Now().Add(v.timeout)); err != nil {
		return nil, fmt.Errorf("atxp.ServerHandshake: %w", err)
	}
	if _, err := conn.Write(header); err != nil {
		return nil, fmt.Errorf("atxp.ServerHandshake: %w: %w", ErrHandshake, err)
	}
	return v.cipherFromSalt(salt)
}

// ClientHandshake performs the client side of the V2 handshake: it reads and
// validates the handshake header and returns the session [Cipher].
func (v *V2) ClientHandshake(conn SecureConn) (Cipher, error) {
	if err := conn.SetReadDeadline(time.Now().Add(v.timeout)); err != nil {
		return nil, fmt.Errorf("atxp.ClientHandshake: %w", err)
	}
	header := make([]byte, handshakeHeaderSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("atxp.ClientHandshake: %w: %w", ErrHandshake, err)
	}
	if string(header[:len(HandshakeMagic)]) != HandshakeMagic {
		return nil, fmt.Errorf("atxp.ClientHandshake: bad magic: %w", ErrHandshake)
	}
	if header[len(HandshakeMagic)] != ProtocolVersionV2 {
		return nil, fmt.Errorf("atxp.ClientHandshake: unsupported version: %w", ErrHandshake)
	}
	salt := header[len(HandshakeMagic)+1:]
	return v.cipherFromSalt(salt)
}

func (v *V2) cipherFromSalt(salt []byte) (Cipher, error) {
	key, err := deriveKey(v.password, salt, v.iterations)
	if err != nil {
		return nil, err
	}
	return newGCMCipher(key)
}

// SerializeV2 encodes msg and its sequence number into the V2 inner plaintext
// envelope. Every variable-length field is length-prefixed, so the payload may
// contain any bytes. The result is the plaintext to be sealed, not the wire
// frame.
func SerializeV2(msg *Message, seq uint64) ([]byte, error) {
	if msg == nil {
		return nil, ErrInvalidFormat
	}

	var payload []byte
	if !msg.Data.IsEmpty() {
		payload = msg.Data.Get()
	}
	username := []byte(msg.Auth.Username)
	filename := []byte(msg.Filename)

	size := 1 + 8 + 4 + (4 + len(payload)) + (4 + len(username)) + (4 + len(filename))
	buf := make([]byte, 0, size)
	buf = append(buf, kindMessage)
	buf = binary.BigEndian.AppendUint64(buf, seq)
	buf = binary.BigEndian.AppendUint32(buf, uint32(msg.Type))
	buf = appendField(buf, payload)
	buf = appendField(buf, username)
	buf = appendField(buf, filename)
	return buf, nil
}

// DeserializeV2 decodes a V2 message envelope into msg and returns the carried
// sequence number. It returns [ErrInvalidEnvelope] for any structural fault.
func DeserializeV2(plaintext []byte, msg *Message) (uint64, error) {
	if msg == nil {
		return 0, ErrInvalidFormat
	}
	r := &envelopeReader{b: plaintext}

	kind, ok := r.readByte()
	if !ok || kind != kindMessage {
		return 0, ErrInvalidEnvelope
	}
	seq, ok := r.readUint64()
	if !ok {
		return 0, ErrInvalidEnvelope
	}
	code, ok := r.readUint32()
	if !ok {
		return 0, ErrInvalidEnvelope
	}
	payload, ok := r.readField()
	if !ok {
		return 0, ErrInvalidEnvelope
	}
	username, ok := r.readField()
	if !ok {
		return 0, ErrInvalidEnvelope
	}
	filename, ok := r.readField()
	if !ok {
		return 0, ErrInvalidEnvelope
	}
	if !r.done() {
		return 0, ErrInvalidEnvelope
	}

	msg.Type = MT(code)
	msg.Data = box.NewSome(payload)
	msg.Auth = Auth{Username: string(username)}
	msg.Filename = string(filename)
	return seq, nil
}

// serializeResponseV2 encodes a response code and sequence number into the V2
// response envelope plaintext.
func serializeResponseV2(code ResponseCode, seq uint64) []byte {
	buf := make([]byte, 0, 1+8+4)
	buf = append(buf, kindResponse)
	buf = binary.BigEndian.AppendUint64(buf, seq)
	buf = binary.BigEndian.AppendUint32(buf, uint32(code))
	return buf
}

// deserializeResponseV2 decodes a V2 response envelope plaintext.
func deserializeResponseV2(plaintext []byte) (ResponseCode, uint64, error) {
	r := &envelopeReader{b: plaintext}
	kind, ok := r.readByte()
	if !ok || kind != kindResponse {
		return ERROR, 0, ErrInvalidEnvelope
	}
	seq, ok := r.readUint64()
	if !ok {
		return ERROR, 0, ErrInvalidEnvelope
	}
	code, ok := r.readUint32()
	if !ok || !r.done() {
		return ERROR, 0, ErrInvalidEnvelope
	}
	return ResponseCode(code), seq, nil
}

// SendV2 serializes, seals and writes a message frame using the default frame
// cap [MaxFrameSizeV2], returning the number of bytes written on the wire. To
// use a custom cap, build a [ClientV2]/[ServerV2] with [WithMaxFrameSize].
func SendV2(conn SecureConn, c Cipher, msg *Message, seq uint64) (int, error) {
	return sendMessageFrame(conn, c, msg, seq, MaxFrameSizeV2)
}

// ReceiveV2 reads, opens and decodes a single message frame using the default
// frame cap [MaxFrameSizeV2], returning the message and its sequence number.
func ReceiveV2(conn SecureConn, c Cipher) (*Message, uint64, error) {
	return receiveMessageFrame(conn, c, MaxFrameSizeV2)
}

// SendResponseV2 seals and writes a response frame using the default frame cap.
func SendResponseV2(conn SecureConn, c Cipher, code ResponseCode, seq uint64) error {
	return sendResponseFrame(conn, c, code, seq, MaxFrameSizeV2)
}

// ReceiveResponseV2 reads, opens and decodes a single response frame using the
// default frame cap.
func ReceiveResponseV2(conn SecureConn, c Cipher) (ResponseCode, uint64, error) {
	return receiveResponseFrame(conn, c, MaxFrameSizeV2)
}

func sendMessageFrame(conn SecureConn, c Cipher, msg *Message, seq uint64, maxFrameSize int) (int, error) {
	plaintext, err := SerializeV2(msg, seq)
	if err != nil {
		return 0, err
	}
	return writeFrame(conn, c, plaintext, maxFrameSize)
}

func receiveMessageFrame(conn SecureConn, c Cipher, maxFrameSize int) (*Message, uint64, error) {
	plaintext, err := readFrame(conn, c, maxFrameSize)
	if err != nil {
		return nil, 0, err
	}
	var msg Message
	seq, err := DeserializeV2(plaintext, &msg)
	if err != nil {
		return nil, 0, err
	}
	return &msg, seq, nil
}

func sendResponseFrame(conn SecureConn, c Cipher, code ResponseCode, seq uint64, maxFrameSize int) error {
	_, err := writeFrame(conn, c, serializeResponseV2(code, seq), maxFrameSize)
	return err
}

func receiveResponseFrame(conn SecureConn, c Cipher, maxFrameSize int) (ResponseCode, uint64, error) {
	plaintext, err := readFrame(conn, c, maxFrameSize)
	if err != nil {
		return ERROR, 0, err
	}
	return deserializeResponseV2(plaintext)
}

// writeFrame seals plaintext and writes a length-prefixed encrypted frame,
// rejecting frames larger than maxFrameSize.
func writeFrame(conn SecureConn, c Cipher, plaintext []byte, maxFrameSize int) (int, error) {
	sealed, err := c.Seal(plaintext)
	if err != nil {
		return 0, fmt.Errorf("atxp.writeFrame: %w", err)
	}
	if len(sealed) > maxFrameSize {
		return 0, ErrFrameTooLarge
	}

	frame := make([]byte, LengthPrefixSize+len(sealed))
	binary.BigEndian.PutUint32(frame, uint32(len(sealed)))
	copy(frame[LengthPrefixSize:], sealed)

	if err := conn.SetWriteDeadline(time.Now().Add(DefaultIOTimeout)); err != nil {
		return 0, fmt.Errorf("atxp.writeFrame: %w", err)
	}
	n, err := conn.Write(frame)
	if err != nil {
		return n, fmt.Errorf("atxp.writeFrame: %w", err)
	}
	return n, nil
}

// readFrame reads a length-prefixed encrypted frame, enforces the size bounds
// against maxFrameSize and returns the opened plaintext.
func readFrame(conn SecureConn, c Cipher, maxFrameSize int) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(DefaultIOTimeout)); err != nil {
		return nil, fmt.Errorf("atxp.readFrame: %w", err)
	}

	var lenBuf [LengthPrefixSize]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > uint32(maxFrameSize) {
		return nil, ErrFrameTooLarge
	}
	if n < NonceSize+GCMTagSize {
		return nil, ErrFrameTooSmall
	}

	sealed := make([]byte, n)
	if _, err := io.ReadFull(conn, sealed); err != nil {
		return nil, err
	}
	return c.Open(sealed)
}

// appendField appends a 4-byte big-endian length followed by the field bytes.
func appendField(buf, field []byte) []byte {
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(field)))
	return append(buf, field...)
}

// envelopeReader is a bounds-checked cursor over a decrypted envelope.
type envelopeReader struct {
	b   []byte
	off int
}

func (r *envelopeReader) readByte() (byte, bool) {
	if r.off+1 > len(r.b) {
		return 0, false
	}
	v := r.b[r.off]
	r.off++
	return v, true
}

func (r *envelopeReader) readUint32() (uint32, bool) {
	if r.off+4 > len(r.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v, true
}

func (r *envelopeReader) readUint64() (uint64, bool) {
	if r.off+8 > len(r.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint64(r.b[r.off:])
	r.off += 8
	return v, true
}

// readField reads a length-prefixed field, copying it out so the returned
// slice does not alias the decrypted buffer.
func (r *envelopeReader) readField() ([]byte, bool) {
	n, ok := r.readUint32()
	if !ok {
		return nil, false
	}
	if r.off+int(n) > len(r.b) {
		return nil, false
	}
	out := make([]byte, n)
	copy(out, r.b[r.off:r.off+int(n)])
	r.off += int(n)
	return out, true
}

func (r *envelopeReader) done() bool {
	return r.off == len(r.b)
}
