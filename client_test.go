package atxp

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/atendi9/capivara/assert"
)

// TestNewClient verifies that NewClient properly initializes the Client instance with credentials.
func TestNewClient(t *testing.T) {
	mockConn := &mockNetworkIO{}
	username := "atendi9_user"
	password := "secure_password"

	client := NewClient(mockConn, username, password)

	assert.Equal(t, mockConn, client.conn.(*mockNetworkIO))
	assert.Equal(t, username, client.auth.Username)
	assert.Equal(t, password, client.auth.Password)
}

// TestClient_SendURL_Success checks if SendURL correctly sends a URL frame and returns OK response.
func TestClient_SendURL_Success(t *testing.T) {
	mockConn := &mockNetworkIO{
		readBuf:  bytes.NewBufferString("RESP:0\n\n"),
		writeBuf: &bytes.Buffer{},
	}
	client := NewClient(mockConn, "user", "pass")

	code, err := client.SendURL("https://atendi9.com/api")

	assert.NoError(t, err)
	assert.Equal(t, OK, code)

	expectedPayload := "URL\t\thttps://atendi9.com/api\t\tAuth:user::pass\n\n"
	assert.Equal(t, expectedPayload, mockConn.writeBuf.String())
}

// TestClient_SendURL_WriteError checks if SendURL fails when the underlying network connection fails to write.
func TestClient_SendURL_WriteError(t *testing.T) {
	mockConn := &mockNetworkIO{
		readBuf:  &bytes.Buffer{},
		writeBuf: &bytes.Buffer{},
		writeErr: errors.New("network write failure"),
	}
	client := NewClient(mockConn, "user", "pass")

	code, err := client.SendURL("https://atendi9.com/api")

	assert.Error(t, err)
	assert.Equal(t, ERROR, code)
}

// TestClient_SendURL_ReceiveError checks if SendURL fails when the connection fails to receive the protocol response response.
func TestClient_SendURL_ReceiveError(t *testing.T) {
	mockConn := &mockNetworkIO{
		readBuf:  bytes.NewBufferString("RESP:invalid_code\n\n"),
		writeBuf: &bytes.Buffer{},
	}
	client := NewClient(mockConn, "user", "pass")

	code, err := client.SendURL("https://atendi9.com/api")

	assert.Error(t, err)
	assert.Equal(t, ERROR, code)
}

// TestClient_SendDocument_Success checks if SendDocument correctly sends raw bytes payload frames and processes an OK status.
func TestClient_SendDocument_Success(t *testing.T) {
	mockConn := &mockNetworkIO{
		readBuf:  bytes.NewBufferString("RESP:0\n\n"),
		writeBuf: &bytes.Buffer{},
	}
	client := NewClient(mockConn, "admin", "secret")
	documentPayload := []byte{0x01, 0x02, 0x03, 0x04}

	code, err := client.SendDocument(documentPayload, "report.pdf")

	assert.NoError(t, err)
	assert.Equal(t, OK, code)

	expectedPayload := "Document\t\t" + string(documentPayload) + "\t\tAuth:admin::secret::report.pdf\n\n"
	assert.Equal(t, expectedPayload, mockConn.writeBuf.String())
}

// TestClient_SendDocument_WriteError checks if SendDocument fails when the network write operation fails.
func TestClient_SendDocument_WriteError(t *testing.T) {
	mockConn := &mockNetworkIO{
		readBuf:  &bytes.Buffer{},
		writeBuf: &bytes.Buffer{},
		writeErr: errors.New("broken pipe"),
	}
	client := NewClient(mockConn, "admin", "secret")

	code, err := client.SendDocument([]byte("pdf_content"), "test.txt")

	assert.Error(t, err)
	assert.Equal(t, ERROR, code)
}

// TestClient_SendNotification_Success checks if SendNotification correctly frames a message and interprets an UNAUTHORIZED result.
func TestClient_SendNotification_Success(t *testing.T) {
	mockConn := &mockNetworkIO{
		readBuf:  bytes.NewBufferString("RESP:2\n\n"), // 2 represents UNAUTHORIZED
		writeBuf: &bytes.Buffer{},
	}
	client := NewClient(mockConn, "alert_system", "token123")

	code, err := client.SendNotification("system_overload")

	assert.NoError(t, err)
	assert.Equal(t, UNAUTHORIZED, code)

	expectedPayload := "Notification\t\tsystem_overload\t\tAuth:alert_system::token123\n\n"
	assert.Equal(t, expectedPayload, mockConn.writeBuf.String())
}

// TestClient_SendNotification_EOF checks if SendNotification returns ERROR when connection reaches EOF unexpected during reading response.
func TestClient_SendNotification_EOF(t *testing.T) {
	mockConn := &mockNetworkIO{
		readBuf:  bytes.NewBufferString(""),
		writeBuf: &bytes.Buffer{},
		readErr:  io.EOF,
	}
	client := NewClient(mockConn, "user", "pass")

	code, err := client.SendNotification("hello")

	assert.Error(t, err)
	assert.Equal(t, ERROR, code)
}
