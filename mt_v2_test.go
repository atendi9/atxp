package atxp

import (
	"fmt"
	"sync"
	"testing"

	"github.com/atendi9/capivara/assert"
)

// TestBuiltinMTRegistered verifies the default message types are present.
func TestBuiltinMTRegistered(t *testing.T) {
	for _, code := range []MT{URL, DOCUMENT, NOTIFICATION} {
		mt, ok := LookupMT(code)
		assert.True(t, ok)
		assert.Equal(t, code, mt.Code)
		assert.NotEmpty(t, mt.Name)
		assert.NotEmpty(t, mt.Description)
	}
}

// TestTypeToStringV2 validates name resolution via the registry.
func TestTypeToStringV2(t *testing.T) {
	assert.Equal(t, "URL", TypeToStringV2(URL))
	assert.Equal(t, "DOCUMENT", TypeToStringV2(DOCUMENT))
	assert.Equal(t, "NOTIFICATION", TypeToStringV2(NOTIFICATION))
	assert.Equal(t, "UNKNOWN", TypeToStringV2(MT(999999)))
}

// TestStringToTypeV2 validates reverse name resolution.
func TestStringToTypeV2(t *testing.T) {
	code, ok := StringToTypeV2("URL")
	assert.True(t, ok)
	assert.Equal(t, URL, code)

	_, ok = StringToTypeV2("NOPE")
	assert.False(t, ok)
}

// TestNewMT validates registration of custom types and duplicate rejection.
func TestNewMT(t *testing.T) {
	const custom MT = 4242
	ok := NewMT(MT_V2{Name: "WEBHOOK", Code: custom, Description: "external webhook registration"})
	assert.True(t, ok)

	// Duplicate code must be rejected.
	dup := NewMT(MT_V2{Name: "WEBHOOK_DUP", Code: custom, Description: "should be rejected"})
	assert.False(t, dup)

	mt, found := LookupMT(custom)
	assert.True(t, found)
	assert.Equal(t, "WEBHOOK", mt.Name)

	// Built-in codes cannot be overridden.
	assert.False(t, NewMT(MT_V2{Name: "X", Code: URL, Description: "override attempt"}))
}

// TestNewMTConcurrent exercises the registry under the race detector.
func TestNewMTConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			NewMT(MT_V2{Name: fmt.Sprintf("T%d", n), Code: MT(10000 + n), Description: "concurrent"})
			_ = TypeToStringV2(MT(10000 + n))
			_, _ = LookupMT(MT(10000 + n))
		}(i)
	}
	wg.Wait()

	mt, ok := LookupMT(MT(10025))
	assert.True(t, ok)
	assert.Equal(t, "T25", mt.Name)
}
