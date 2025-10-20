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
		name           string
		message        interface{}
		validJSON      string
		invalidJSON    []string // JSON strings that should fail to unmarshal
		corruptedJSON  string   // Malformed JSON
	}{
		{
			name:        "AddKeyMessage",
			message:     &AddKeyMessage{},
			validJSON:   `{"actor":"a","time":"t","public-key":"pk"}`,
			invalidJSON: []string{`{"time":"t","public-key":"pk"}`}, // Missing actor
		},
		{
			name:        "RevokeKeyMessage",
			message:     &RevokeKeyMessage{},
			validJSON:   `{"actor":"a","time":"t","public-key":"pk"}`,
			invalidJSON: []string{`{"actor":"a","time":"t"}`}, // Missing public-key
		},
		{
			name:        "RevokeKeyThirdPartyMessage",
			message:     &RevokeKeyThirdPartyMessage{},
			validJSON:   `{"action":"a","revocation-token":"rt"}`,
			invalidJSON: []string{`{"action":"a"}`}, // Missing revocation-token
		},
		{
			name:        "MoveIdentityMessage",
			message:     &MoveIdentityMessage{},
			validJSON:   `{"old-actor":"oa","new-actor":"na","time":"t"}`,
			invalidJSON: []string{`{"new-actor":"na","time":"t"}`}, // Missing old-actor
		},
		{
			name:        "BurnDownMessage",
			message:     &BurnDownMessage{},
			validJSON:   `{"actor":"a","operator":"o","time":"t"}`,
			invalidJSON: []string{`{"operator":"o","time":"t"}`}, // Missing actor
		},
		{
			name:        "FireproofMessage",
			message:     &FireproofMessage{},
			validJSON:   `{"actor":"a","time":"t"}`,
			invalidJSON: []string{`{"time":"t"}`}, // Missing actor
		},
		{
			name:        "UndoFireproofMessage",
			message:     &UndoFireproofMessage{},
			validJSON:   `{"actor":"a","time":"t"}`,
			invalidJSON: []string{`{"time":"t"}`}, // Missing actor
		},
		{
			name:        "AddAuxDataMessage",
			message:     &AddAuxDataMessage{},
			validJSON:   `{"actor":"a","aux-type":"at","aux-data":"ad","aux-id":"ai","time":"t"}`,
			invalidJSON: []string{`{"aux-type":"at","aux-data":"ad","time":"t"}`}, // Missing actor
		},
		{
			name:        "RevokeAuxDataMessage",
			message:     &RevokeAuxDataMessage{},
			validJSON:   `{"actor":"a","aux-type":"at","aux-data":"ad","aux-id":"ai","time":"t"}`,
			invalidJSON: []string{`{"aux-type":"at","time":"t"}`}, // Missing actor and aux-data/aux-id
		},
		{
			name:        "QueryMessage",
			message:     &QueryMessage{},
			validJSON:   `{"actor":"a"}`,
			invalidJSON: []string{`{}`}, // Missing actor
		},
		{
			name:        "CheckpointMessage",
			message:     &CheckpointMessage{},
			validJSON:   `{"time":"t","from-directory":"fd","from-root":"fr","from-public-key":"fpk","to-directory":"td","to-validated-root":"tvr"}`,
			invalidJSON: []string{`{"from-directory":"fd","from-root":"fr"}`}, // Missing fields
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name+"-Valid", func(t *testing.T) {
			// Test unmarshalling valid JSON
			err := json.Unmarshal([]byte(tc.validJSON), tc.message)
			assert.NoError(t, err, "Should unmarshal valid JSON without error")

			// Test marshalling and re-unmarshalling
			jsonData, err := json.Marshal(tc.message)
			assert.NoError(t, err, "Should marshal to JSON without error")
			err = json.Unmarshal(jsonData, tc.message)
			assert.NoError(t, err, "Should unmarshal back from marshalled JSON without error")
		})

		if len(tc.invalidJSON) > 0 {
			t.Run(tc.name+"-Invalid", func(t *testing.T) {
				for _, invalid := range tc.invalidJSON {
					err := json.Unmarshal([]byte(invalid), tc.message)
					assert.Error(t, err, "Should return an error for JSON with missing fields")
				}
			})
		}

		if tc.corruptedJSON != "" {
			t.Run(tc.name+"-Corrupted", func(t *testing.T) {
				err := json.Unmarshal([]byte(tc.corruptedJSON), tc.message)
				assert.Error(t, err, "Should return an error for corrupted JSON")
			})
		}
	}
}
