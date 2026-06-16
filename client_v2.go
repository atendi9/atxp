// Package atxp implements the ATXP (Atendi9 Transmission Exchange Protocol) wire protocol framing and transport layer.
//   - Copyright (c) 2026 Atendi9
package atxp

import (
	"fmt"

	"github.com/atendi9/box"
)

// ClientV2 is a secure ATXP V2 client bound to a single connection. It performs
// the handshake on construction and thereafter encrypts every frame and tracks
// sequence numbers for replay protection.
//
// ClientV2 is NOT safe for concurrent use by multiple goroutines; serialize
// calls or use one client per goroutine.
type ClientV2 struct {
	conn         SecureConn
	cipher       Cipher
	username     string
	maxFrameSize int
	sendSeq      uint64
	recvSeq      uint64
}

// NewClientV2 derives the session key via the V2 client handshake over conn and
// returns a ready client. The password is used only to derive the encryption
// key and is never transmitted. username identifies the caller to the server's
// AuthHandlerV2.
func NewClientV2(conn SecureConn, password, username string, opts ...OptionV2) (*ClientV2, error) {
	v, err := NewV2(password, opts...)
	if err != nil {
		return nil, err
	}
	cipher, err := v.ClientHandshake(conn)
	if err != nil {
		return nil, fmt.Errorf("atxp.NewClientV2: %w", err)
	}
	return &ClientV2{conn: conn, cipher: cipher, username: username, maxFrameSize: v.maxFrameSize}, nil
}

// SendURL transmits a URL message frame and returns the server's response code.
func (c *ClientV2) SendURL(url string) (ResponseCode, error) {
	return c.send(URL, []byte(url), "")
}

// SendDocument transmits a binary document with an optional filename. The
// payload may contain arbitrary bytes (e.g. a PDF); the length-prefixed
// envelope carries it losslessly.
func (c *ClientV2) SendDocument(document []byte, filename string) (ResponseCode, error) {
	return c.send(DOCUMENT, document, filename)
}

// SendNotification transmits a notification message frame.
func (c *ClientV2) SendNotification(message string) (ResponseCode, error) {
	return c.send(NOTIFICATION, []byte(message), "")
}

// Send transmits a frame of an arbitrary (possibly custom, see [NewMT]) message
// type. filename is only meaningful for document-like types and may be empty.
func (c *ClientV2) Send(messageType MT, data []byte, filename string) (ResponseCode, error) {
	return c.send(messageType, data, filename)
}

// Close terminates the underlying connection.
func (c *ClientV2) Close() error {
	return c.conn.Close()
}

func (c *ClientV2) send(messageType MT, data []byte, filename string) (ResponseCode, error) {
	c.sendSeq++
	msg := &Message{
		Type:     messageType,
		Data:     box.NewSome(data),
		Auth:     Auth{Username: c.username},
		Filename: filename,
	}
	if _, err := sendMessageFrame(c.conn, c.cipher, msg, c.sendSeq, c.maxFrameSize); err != nil {
		return ERROR, fmt.Errorf("atxp.ClientV2.send: %w", err)
	}

	code, seq, err := receiveResponseFrame(c.conn, c.cipher, c.maxFrameSize)
	if err != nil {
		return ERROR, fmt.Errorf("atxp.ClientV2.send: %w", err)
	}
	if seq <= c.recvSeq {
		return ERROR, ErrReplay
	}
	c.recvSeq = seq
	return code, nil
}
