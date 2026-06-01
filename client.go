// Package atxp implements the ATXP (Atendi9 Transmission Exchange Protocol) wire protocol framing and transport layer.
//   - Copyright (c) 2026 Atendi9
package atxp

import (
	"fmt"

	"github.com/atendi9/box"
)

// Client represents an ATXP protocol client session wrapping an active network connection.
type Client struct {
	conn NetworkIO
	auth Auth
}

// NewClient instantiates a new [Client] reference associated with a specific connection and credentials.
func NewClient(conn NetworkIO, username, password string) *Client {
	return &Client{
		conn: conn,
		auth: Auth{
			Username: username,
			Password: password,
		},
	}
}

// SendURL transmits a dedicated URL message frame payload using the internal [Client] connection state.
func (c *Client) SendURL(url string) (ResponseCode, error) {
	msg := &Message{
		Type: URL,
		Data: box.NewSome([]byte(url)),
		Auth: c.auth,
	}

	_, err := Send(c.conn, msg)
	if err != nil {
		return ERROR, fmt.Errorf("failed to send URL frame: %w", err)
	}

	return ReceiveResponse(c.conn)
}

// SendDocument transmits a dedicated document byte slice frame payload with an optional filename using the internal [Client] connection state.
func (c *Client) SendDocument(document []byte, filename string) (ResponseCode, error) {
	msg := &Message{
		Type:     DOCUMENT,
		Data:     box.NewSome(document),
		Auth:     c.auth,
		Filename: filename,
	}

	_, err := Send(c.conn, msg)
	if err != nil {
		return ERROR, fmt.Errorf("failed to send document frame: %w", err)
	}

	return ReceiveResponse(c.conn)
}

// SendNotification transmits a dedicated alert or notification payload frame using the internal [Client] connection state.
func (c *Client) SendNotification(message string) (ResponseCode, error) {
	msg := &Message{
		Type: NOTIFICATION,
		Data: box.NewSome([]byte(message)),
		Auth: c.auth,
	}

	_, err := Send(c.conn, msg)
	if err != nil {
		return ERROR, fmt.Errorf("failed to send notification frame: %w", err)
	}

	return ReceiveResponse(c.conn)
}
