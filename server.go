// Package atxp implements the ATXP (Atendi9 Transmission Exchange Protocol) wire protocol framing and transport layer.
//   - Copyright (c) 2026 Atendi9
package atxp

import (
	"errors"
	"net"
	"strings"

	"github.com/atendi9/box"
)

// AuthData encapsulates optional authentication metadata that may be associated with incoming ATXP messages, allowing handlers to access user credentials or session information when necessary.
type AuthData box.Optional[map[string]any]

// Handler defines a function signature capable of routing and processing incoming decrypted ATXP message payloads.
type Handler func(msg *Message, authData AuthData) ResponseCode

// AuthHandler defines a function signature for authentication logic, allowing the server to verify credentials and optionally return additional authentication data for use in message handling.
type AuthHandler func(username, password string) (authorized bool, data AuthData)

// Server manages inbound connection routing rules, payload verification, and session authentication lifecycles.
type Server struct {
	handlers map[MT]Handler
	authFn   AuthHandler
}

// NewServer configures a brand new [Server] context setup with no default active route bindings.
func NewServer(authFn AuthHandler) *Server {
	return &Server{
		handlers: make(map[MT]Handler),
		authFn:   authFn,
	}
}

// RegisterHandler registers a specific [Handler] callback mapping execution logic against an ATXP framing type.
func (s *Server) RegisterHandler(messageType MT, handler Handler) {
	s.handlers[messageType] = handler
}

// Serve initializes a synchronous network event poll looping across an active [net.Listener] mapping interface.
func (s *Server) Serve(listener net.Listener) error {
	if listener == nil {
		return errors.New("listener cannot be nil")
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		go s.HandleConnection(conn)
	}
}

// HandleConnection processes single network stream frames incoming through standard [NetworkIO] implementations.
func (s *Server) HandleConnection(conn NetworkIO) {
	defer conn.Close()

	for {
		rawMsg, err := Receive(conn)
		if err != nil {
			return
		}
		if rawMsg == "" {
			return
		}

		var msg Message
		err = Deserialize(rawMsg, &msg)
		if err != nil {
			_, _ = SendResponse(conn, ERROR)
			return
		}

		var authData AuthData

		if s.authFn != nil {
			authorized, data := s.authFn(msg.Auth.Username, msg.Auth.Password)
			if !authorized {
				_, _ = SendResponse(conn, UNAUTHORIZED)
				return
			}
			authData = data
		}

		handler, exists := s.handlers[msg.Type]
		if !exists {
			_, _ = SendResponse(conn, ERROR)
			continue
		}

		code := handler(&msg, authData)
		_, _ = SendResponse(conn, code)
	}
}

// ValidateURLHandler provides a standard fallback business logic example validation for standard URL structures.
func ValidateURLHandler() Handler {
	return func(msg *Message, _ AuthData) ResponseCode {
		if msg.Data.IsEmpty() {
			return ERROR
		}

		urlStr := string(msg.Data.Get())
		if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
			return ERROR
		}

		return OK
	}
}

// ValidateDocumentHandler provides a basic validation ensuring payload sizes match requirements.
func ValidateDocumentHandler(maxBytes int) Handler {
	return func(msg *Message, _ AuthData) ResponseCode {
		if msg.Data.IsEmpty() {
			return ERROR
		}

		if len(msg.Data.Get()) > maxBytes || len(msg.Data.Get()) == 0 {
			return ERROR
		}

		return OK
	}
}
