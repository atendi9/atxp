// Package atxp implements the ATXP (Atendi9 Transmission Exchange Protocol) wire protocol framing and transport layer.
//   - Copyright (c) 2026 Atendi9
package atxp

import (
	"errors"
	"net"
	"strings"
)

// Handler defines a function signature capable of routing and processing incoming decrypted ATXP message payloads.
type Handler func(msg *Message) ResponseCode

// Server manages inbound connection routing rules, payload verification, and session authentication lifecycles.
type Server struct {
	handlers map[MT]Handler
	authFn   func(username, password string) bool
}

// NewServer configures a brand new [Server] context setup with no default active route bindings.
func NewServer(authFn func(username, password string) bool) *Server {
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

		if s.authFn != nil && !s.authFn(msg.Auth.Username, msg.Auth.Password) {
			_, _ = SendResponse(conn, UNAUTHORIZED)
			return
		}

		handler, exists := s.handlers[msg.Type]
		if !exists {
			_, _ = SendResponse(conn, ERROR)
			continue
		}

		code := handler(&msg)
		_, _ = SendResponse(conn, code)
	}
}

// ValidateURLHandler provides a standard fallback business logic example validation for standard URL structures.
func ValidateURLHandler() Handler {
	return func(msg *Message) ResponseCode {
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
	return func(msg *Message) ResponseCode {
		if msg.Data.IsEmpty() {
			return ERROR
		}

		if len(msg.Data.Get()) > maxBytes || len(msg.Data.Get()) == 0 {
			return ERROR
		}

		return OK
	}
}
