// Package atxp implements the ATXP (Atendi9 Transmission Exchange Protocol) wire protocol framing and transport layer.
//   - Copyright (c) 2026 Atendi9
package atxp

import (
	"errors"
	"net"
	"sync"
)

// AuthHandlerV2 authorizes a connection by username only. Unlike the V1
// [AuthHandler], it receives no password: in V2 the password is the encryption
// key and is never transmitted, so the fact that the client's frames decrypt
// successfully already proves it holds the shared secret. The username is used
// for identity and to attach per-user [AuthData].
type AuthHandlerV2 func(username string) (authorized bool, data AuthData)

// ServerV2 is a secure ATXP V2 server. It performs the handshake per
// connection, decrypts and routes frames to registered handlers, and enforces
// replay protection via per-connection sequence numbers.
//
// ServerV2 is safe for concurrent use: handler registration and lookup are
// guarded by a mutex, and each connection is handled in its own goroutine.
type ServerV2 struct {
	v        *V2
	authFn   AuthHandlerV2
	mu       sync.RWMutex
	handlers map[MT]Handler
}

// NewServerV2 creates a secure server using the shared password to derive
// per-connection session keys. authFn may be nil to accept any client that
// holds the password.
func NewServerV2(password string, authFn AuthHandlerV2, opts ...OptionV2) (*ServerV2, error) {
	v, err := NewV2(password, opts...)
	if err != nil {
		return nil, err
	}
	return &ServerV2{
		v:        v,
		authFn:   authFn,
		handlers: make(map[MT]Handler),
	}, nil
}

// RegisterHandler binds a [Handler] to a message type. It is safe for
// concurrent use.
func (s *ServerV2) RegisterHandler(messageType MT, handler Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[messageType] = handler
}

func (s *ServerV2) handler(messageType MT) (Handler, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.handlers[messageType]
	return h, ok
}

// Serve accepts connections on listener and handles each in its own goroutine
// until Accept fails. It returns the Accept error that ended the loop.
func (s *ServerV2) Serve(listener net.Listener) error {
	if listener == nil {
		return errors.New("atxp.ServerV2.Serve: listener cannot be nil")
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.HandleConnection(conn)
	}
}

// HandleConnection runs the handshake and then the per-connection frame loop:
// receive, verify sequence ordering, authorize, route, respond. Each response
// also carries a monotonic sequence number for the client's replay checks.
func (s *ServerV2) HandleConnection(conn SecureConn) {
	defer conn.Close()

	cipher, err := s.v.ServerHandshake(conn)
	if err != nil {
		return
	}

	maxFrameSize := s.v.maxFrameSize
	var recvSeq, sendSeq uint64
	for {
		msg, seq, err := receiveMessageFrame(conn, cipher, maxFrameSize)
		if err != nil {
			return
		}
		if seq <= recvSeq {
			sendSeq++
			_ = sendResponseFrame(conn, cipher, ERROR, sendSeq, maxFrameSize)
			return
		}
		recvSeq = seq

		var authData AuthData
		if s.authFn != nil {
			authorized, data := s.authFn(msg.Auth.Username)
			if !authorized {
				sendSeq++
				_ = sendResponseFrame(conn, cipher, UNAUTHORIZED, sendSeq, maxFrameSize)
				return
			}
			authData = data
		}

		handler, ok := s.handler(msg.Type)
		if !ok {
			sendSeq++
			_ = sendResponseFrame(conn, cipher, ERROR, sendSeq, maxFrameSize)
			continue
		}

		code := handler(msg, authData)
		sendSeq++
		_ = sendResponseFrame(conn, cipher, code, sendSeq, maxFrameSize)
	}
}
