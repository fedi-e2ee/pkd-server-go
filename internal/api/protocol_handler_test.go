package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/stretchr/testify/assert"
)

func TestHandleProtocolMessage_UnsupportedAction(t *testing.T) {
	// Create a new server with a mock repository and sigsum client
	server := &Server{
		actionHandlers: make(map[string]protocolActionHandler),
	}

	// Create a sample protocol message with an unsupported action
	protocolMsg := protocol.ProtocolMessage{
		PKDContext: protocol.PKDContextV1,
		Action:     "UnsupportedAction",
	}

	// Marshal the protocol message to JSON
	protocolMsgJSON, err := json.Marshal(protocolMsg)
	assert.NoError(t, err)

	// Create a new HTTP request
	req, err := http.NewRequest("POST", "/protocol", bytes.NewBuffer(protocolMsgJSON))
	assert.NoError(t, err)

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the handler
	server.handleProtocolMessage(rr, req)

	// Check the status code and response body
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Unsupported action: UnsupportedAction")
}

func TestHandleProtocolMessage_ActivityPubSignature(t *testing.T) {
	// Create a new server with a mock repository and sigsum client
	server := &Server{
		actionHandlers: make(map[string]protocolActionHandler),
	}

	// Create a sample protocol message
	protocolMsg := protocol.ProtocolMessage{
		PKDContext: protocol.PKDContextV1,
		Action:     "AddKey",
	}

	// Marshal the protocol message to JSON
	protocolMsgJSON, err := json.Marshal(protocolMsg)
	assert.NoError(t, err)

	// Create a new HTTP request
	req, err := http.NewRequest("POST", "/protocol", bytes.NewBuffer(protocolMsgJSON))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/activity+json")

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the handler
	server.handleProtocolMessage(rr, req)

	// Check the status code and response body
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing Signature header for ActivityPub request")
}
