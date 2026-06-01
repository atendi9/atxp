// Package atxp implements the ATXP (Atendi9 Transmission Exchange Protocol) wire protocol framing and transport layer.
//   - Copyright (c) 2026 Atendi9
package atxp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/atendi9/box"
)

// MT represents the numeric type identifier for ATXP message frames.
type MT int

// Message Types constants representing supported ATXP frames.
const (
	URL          MT = 0
	DOCUMENT     MT = 1
	NOTIFICATION MT = 2
)

var (
	// ErrInvalidFormat occurs when an ATXP packet does not comply with the protocol syntax.
	ErrInvalidFormat = errors.New("malformed atxp packet protocol")
)

// Message represents an internal ATXP protocol message frame.
// It wraps the type, an optional byte payload data structure, and credentials.
type Message struct {
	Type     MT
	Data     box.Optional[[]byte]
	Auth     Auth
	Filename string
}

// ResponseCode represents the status of an ATXP protocol handshake or message processing result.
type ResponseCode int

// Response Codes constants representing ATXP protocol handshake results.
const (
	OK ResponseCode = iota
	ERROR
	UNAUTHORIZED
)

// Auth contains credentials for validating connection or message authority.
type Auth struct {
	Username string
	Password string
}

// NetworkIO abstracts the net.Conn interface for easy testing and dependency injection.
type NetworkIO interface {
	io.ReadWriter
	Close() error
}

// TypeToString converts a numeric ATXP type to its equivalent string representation.
func TypeToString(messageType MT) string {
	switch messageType {
	case URL:
		return "URL"
	case DOCUMENT:
		return "Document"
	case NOTIFICATION:
		return "Notification"
	default:
		return "UNKNOWN"
	}
}

// StringToType converts an ATXP string type representation back to its numeric value.
func StringToType(str string) MT {
	switch str {
	case "URL":
		return URL
	case "Document":
		return DOCUMENT
	case "Notification":
		return NOTIFICATION
	default:
		return -1
	}
}

// Serialize encodes a [Message] into a raw byte slice payload according to the ATXP wire protocol.
func Serialize(msg *Message) ([]byte, error) {
	if msg == nil {
		return nil, ErrInvalidFormat
	}

	typeStr := TypeToString(msg.Type)

	var builder strings.Builder
	if msg.Data.IsEmpty() {
		msg.Data = box.NewSome([]byte{})
	}
	builder.Grow(len(typeStr) + 4 + len(msg.Data.Get()) + 13 + len(msg.Auth.Username) + len(msg.Auth.Password) + len(msg.Filename))

	builder.WriteString(typeStr)
	builder.WriteString("\t\t")
	builder.Write(msg.Data.Get())
	builder.WriteString("\t\tAuth:")
	builder.WriteString(msg.Auth.Username)
	builder.WriteString("::")
	builder.WriteString(msg.Auth.Password)
	if msg.Type == DOCUMENT && msg.Filename != "" {
		builder.WriteString("::")
		builder.WriteString(msg.Filename)
	}
	builder.WriteString("\n\n")

	return []byte(builder.String()), nil
}

// Deserialize decodes a raw string packet back into the provided [Message] structure reference based on ATXP syntax.
func Deserialize(buffer string, msg *Message) error {
	if msg == nil || buffer == "" {
		return ErrInvalidFormat
	}

	typePartIdx := strings.Index(buffer, "\t\t")
	if typePartIdx == -1 {
		return ErrInvalidFormat
	}
	typeStr := buffer[:typePartIdx]

	authPartIdx := strings.Index(buffer, "\t\tAuth:")
	if authPartIdx == -1 {
		return ErrInvalidFormat
	}

	dataStr := buffer[typePartIdx+2 : authPartIdx]

	tailIdx := strings.Index(buffer, "\n\n")
	if tailIdx == -1 {
		return ErrInvalidFormat
	}

	authStr := buffer[authPartIdx+7 : tailIdx]
	parts := strings.Split(authStr, "::")
	if len(parts) < 2 {
		return ErrInvalidFormat
	}

	msg.Type = StringToType(typeStr)
	msg.Auth.Username = parts[0]
	msg.Auth.Password = parts[1]
	if msg.Type == DOCUMENT && len(parts) > 2 {
		msg.Filename = parts[2]
	}
	msg.Data = box.NewSome([]byte(dataStr))

	return nil
}

// CreateServer establishes a TCP network listener for incoming ATXP connections at the specified local port binding.
func CreateServer(port int) (net.Listener, error) {
	addr := fmt.Sprintf(":%d", port)
	return net.Listen("tcp", addr)
}

// CreateTLSServer establishes a secure TLS network listener for incoming ATXP connections using the provided server certificate configuration.
func CreateTLSServer(port int, config *tls.Config) (net.Listener, error) {
	if config == nil {
		return nil, errors.New("tls configuration cannot be nil")
	}
	addr := fmt.Sprintf(":%d", port)
	return tls.Listen("tcp", addr, config)
}

// ConnectClient dials an outbound virtual raw network channel interface targeting a remote ATXP host destination.
func ConnectClient(host string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	return net.Dial("tcp", addr)
}

// ConnectTLSClient dials an outbound secure network channel interface targeting a remote ATXP host destination over TLS.
func ConnectTLSClient(host string, port int, config *tls.Config) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	return tls.Dial("tcp", addr, config)
}

// CloseClient terminates the provided connection safely.
func CloseClient(conn io.Closer) error {
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// Receive continuously pulls incoming bytes out of a custom [NetworkIO] reference stream container until a trailing ATXP sequence header is hit.
func Receive(conn NetworkIO) (string, error) {
	var builder strings.Builder
	buf := make([]byte, 1)

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			builder.WriteByte(buf[0])
			if strings.HasSuffix(builder.String(), "\n\n") {
				break
			}
		}
		if err != nil {
			if err == io.EOF {
				return builder.String(), nil
			}
			return "", err
		}
	}
	return builder.String(), nil
}

// Send serializes a [Message] and transmits it through the provided [NetworkIO] implementation using ATXP framing.
func Send(conn NetworkIO, msg *Message) (int, error) {
	payload, err := Serialize(msg)
	if err != nil {
		return 0, err
	}

	return conn.Write(payload)
}

// SendResponse flushes an ATXP status acknowledgment payload segment back to the underlying socket connection.
func SendResponse(conn NetworkIO, responseCode ResponseCode) (ResponseCode, error) {
	respStr := fmt.Sprintf("RESP:%d\n\n", responseCode)
	code, err := conn.Write([]byte(respStr))
	if err != nil {
		return ERROR, err
	}
	return ResponseCode(code), nil
}

// ReceiveResponse parses an incoming ATXP acknowledgment envelope to retrieve status responses from a [NetworkIO] stream.
func ReceiveResponse(conn NetworkIO) (ResponseCode, error) {
	buffer, err := Receive(conn)
	if err != nil && err != io.EOF {
		return ERROR, err
	}
	if buffer == "" {
		return ERROR, io.EOF
	}

	var code ResponseCode
	_, err = fmt.Sscanf(buffer, "RESP:%d\n\n", &code)
	if err != nil {
		return ERROR, ErrInvalidFormat
	}

	return code, nil
}
