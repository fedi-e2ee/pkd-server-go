package protocol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProtocolMessage(t *testing.T) {
	// Create a sample AddKeyMessage
	addKeyMsg := AddKeyMessage{
		Actor:     "test-actor",
		Time:      "2024-01-01T00:00:00Z",
		PublicKey: "test-public-key",
	}

	// Marshal the AddKeyMessage to JSON
	addKeyMsgJSON, err := json.Marshal(addKeyMsg)
	assert.NoError(t, err)

	// Create a ProtocolMessage
	protocolMsg := ProtocolMessage{
		PKDContext:       "test-context",
		Action:           "AddKey",
		KeyID:            "test-key-id",
		Message:          addKeyMsgJSON,
		RecentMerkleRoot: "test-merkle-root",
		Signature:        "test-signature",
		SymmetricKeys: map[string]string{
			"key1": "value1",
		},
		OTP: "123456",
	}

	// Marshal the ProtocolMessage to JSON
	protocolMsgJSON, err := json.Marshal(protocolMsg)
	assert.NoError(t, err)

	// Unmarshal the JSON back into a ProtocolMessage
	var unmarshalledMsg ProtocolMessage
	err = json.Unmarshal(protocolMsgJSON, &unmarshalledMsg)
	assert.NoError(t, err)

	// Assert that the unmarshalled message is equal to the original
	assert.Equal(t, protocolMsg, unmarshalledMsg)

	// Unmarshal the inner message into an AddKeyMessage
	var unmarshalledAddKeyMsg AddKeyMessage
	err = json.Unmarshal(unmarshalledMsg.Message, &unmarshalledAddKeyMsg)
	assert.NoError(t, err)
	assert.Equal(t, addKeyMsg, unmarshalledAddKeyMsg)
}

func TestSignedMessage(t *testing.T) {
	// Create a sample AddKeyMessage
	addKeyMsg := AddKeyMessage{
		Actor:     "test-actor",
		Time:      "2024-01-01T00:00:00Z",
		PublicKey: "test-public-key",
	}

	// Marshal the AddKeyMessage to JSON
	addKeyMsgJSON, err := json.Marshal(addKeyMsg)
	assert.NoError(t, err)

	// Create a SignedMessage
	signedMsg := SignedMessage{
		PKDContext:       "test-context",
		Action:           "AddKey",
		Message:          addKeyMsgJSON,
		RecentMerkleRoot: "test-merkle-root",
	}

	// Marshal the SignedMessage to JSON
	signedMsgJSON, err := json.Marshal(signedMsg)
	assert.NoError(t, err)

	// Unmarshal the JSON back into a SignedMessage
	var unmarshalledMsg SignedMessage
	err = json.Unmarshal(signedMsgJSON, &unmarshalledMsg)
	assert.NoError(t, err)

	// Assert that the unmarshalled message is equal to the original
	assert.Equal(t, signedMsg, unmarshalledMsg)
}

func TestMessageStructs(t *testing.T) {
	testCases := []struct {
		name     string
		message  interface{}
		jsonData string
	}{
		{
			name:     "AddKeyMessage",
			message:  &AddKeyMessage{},
			jsonData: `{"actor":"a","time":"t","public-key":"pk"}`,
		},
		{
			name:     "RevokeKeyMessage",
			message:  &RevokeKeyMessage{},
			jsonData: `{"actor":"a","time":"t","public-key":"pk"}`,
		},
		{
			name:     "RevokeKeyThirdPartyMessage",
			message:  &RevokeKeyThirdPartyMessage{},
			jsonData: `{"action":"a","revocation-token":"rt"}`,
		},
		{
			name:     "MoveIdentityMessage",
			message:  &MoveIdentityMessage{},
			jsonData: `{"old-actor":"oa","new-actor":"na","time":"t"}`,
		},
		{
			name:     "BurnDownMessage",
			message:  &BurnDownMessage{},
			jsonData: `{"actor":"a","operator":"o","time":"t"}`,
		},
		{
			name:     "FireproofMessage",
			message:  &FireproofMessage{},
			jsonData: `{"actor":"a","time":"t"}`,
		},
		{
			name:     "UndoFireproofMessage",
			message:  &UndoFireproofMessage{},
			jsonData: `{"actor":"a","time":"t"}`,
		},
		{
			name:     "AddAuxDataMessage",
			message:  &AddAuxDataMessage{},
			jsonData: `{"actor":"a","aux-type":"at","aux-data":"ad","aux-id":"ai","time":"t"}`,
		},
		{
			name:     "RevokeAuxDataMessage",
			message:  &RevokeAuxDataMessage{},
			jsonData: `{"actor":"a","aux-type":"at","aux-data":"ad","aux-id":"ai","time":"t"}`,
		},
		{
			name:     "QueryMessage",
			message:  &QueryMessage{},
			jsonData: `{"actor":"a"}`,
		},
		{
			name:     "CheckpointMessage",
			message:  &CheckpointMessage{},
			jsonData: `{"time":"t","from-directory":"fd","from-root":"fr","from-public-key":"fpk","to-directory":"td","to-validated-root":"tvr"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test unmarshalling
			err := json.Unmarshal([]byte(tc.jsonData), tc.message)
			assert.NoError(t, err)

			// Test marshalling
			jsonData, err := json.Marshal(tc.message)
			assert.NoError(t, err)

			// Unmarshal again and compare
			var unmarshalledMsg interface{}
			err = json.Unmarshal(jsonData, &unmarshalledMsg)
			assert.NoError(t, err)
		})
	}
}
