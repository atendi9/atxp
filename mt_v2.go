// Package atxp implements the ATXP (Atendi9 Transmission Exchange Protocol) wire protocol framing and transport layer.
//   - Copyright (c) 2026 Atendi9
package atxp

import "sync"

// MT_V2 describes a registered ATXP V2 message type. Unlike the V1 fixed enum,
// V2 message types are registrable at runtime so that callers outside this
// package can define their own framing categories (for example a webhook
// registration URL, a storage document, or an event-driven notification).
type MT_V2 struct {
	// Name is the human-readable identifier transmitted on the wire is NOT
	// used for routing; routing is done by Code. Name is metadata for tooling
	// and diagnostics.
	Name string
	// Code is the numeric routing identifier. It must be unique and, because it
	// is serialized as a big-endian uint32, must be in the range [0, 2^32).
	Code MT
	// Description documents the intended use of the message type.
	Description string
}

// mtRegistry holds the registered V2 message types. It is safe for concurrent
// use: registration takes a write lock, lookups take a read lock.
var mtRegistry = struct {
	sync.RWMutex
	m map[MT]MT_V2
}{
	m: map[MT]MT_V2{
		URL:          {Name: "URL", Code: URL, Description: "Used for transmitting URLs across the network, it can be used to register a webhook."},
		DOCUMENT:     {Name: "DOCUMENT", Code: DOCUMENT, Description: "Used for transferring files. Can be used for storage servers."},
		NOTIFICATION: {Name: "NOTIFICATION", Code: NOTIFICATION, Description: "Used to transmit JSON or events. Can be used in an event-driven architecture."},
	},
}

// NewMT registers a new ATXP V2 message type. It returns false (and registers
// nothing) when the Code is already in use, preventing accidental override of
// the built-in or previously registered types. It is safe for concurrent use.
func NewMT(mt MT_V2) bool {
	mtRegistry.Lock()
	defer mtRegistry.Unlock()

	if _, exists := mtRegistry.m[mt.Code]; exists {
		return false
	}
	mtRegistry.m[mt.Code] = mt
	return true
}

// LookupMT returns the registered [MT_V2] for the given code and whether it
// exists. It is safe for concurrent use.
func LookupMT(code MT) (MT_V2, bool) {
	mtRegistry.RLock()
	defer mtRegistry.RUnlock()
	mt, ok := mtRegistry.m[code]
	return mt, ok
}

// TypeToStringV2 converts a registered message type code to its Name, or
// "UNKNOWN" when the code is not registered. It is safe for concurrent use.
func TypeToStringV2(code MT) string {
	if mt, ok := LookupMT(code); ok {
		return mt.Name
	}
	return "UNKNOWN"
}

// StringToTypeV2 resolves a registered message type Name back to its code. The
// boolean result is false when no registered type carries that name. It is safe
// for concurrent use.
func StringToTypeV2(name string) (MT, bool) {
	mtRegistry.RLock()
	defer mtRegistry.RUnlock()
	for code, mt := range mtRegistry.m {
		if mt.Name == name {
			return code, true
		}
	}
	return MT(-1), false
}
