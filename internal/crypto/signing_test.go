package crypto_test

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/fedi-e2ee/pkd-server-go/internal/crypto"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/gowebpki/jcs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignedMessage_SigningAndVerification(t *testing.T) {
	// 1. Generate a new Ed25519 key pair.
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// 2. Create a sample message payload.
	addKeyMsg := protocol.AddKeyMessage{
		Actor:     "test@example.com",
		Time:      "2024-05-20T12:00:00Z",
		PublicKey: crypto.EncodePublicKey(publicKey),
	}
	addKeyMsgJSON, err := json.Marshal(addKeyMsg)
	require.NoError(t, err)

	// 3. Create the message to be signed.
	signedMsg := protocol.SignedMessage{
		PKDContext:       "https://github.com/fedi-e2ee/public-key-directory/v1",
		Action:           "AddKey",
		Message:          addKeyMsgJSON,
		RecentMerkleRoot: "some-merkle-root",
	}

	// 4. Marshal the SignedMessage to canonical JSON.
	tempBytes, err := json.Marshal(signedMsg)
	require.NoError(t, err)
	signedMsgBytes, err := jcs.Transform(tempBytes)
	require.NoError(t, err)

	// 5. Sign the message.
	signature, err := crypto.SignMessage(privateKey, signedMsgBytes)
	require.NoError(t, err)

	// 6. Create the full ProtocolMessage for verification.
	protocolMsg := &protocol.ProtocolMessage{
		PKDContext:       signedMsg.PKDContext,
		Action:           signedMsg.Action,
		Message:          signedMsg.Message,
		RecentMerkleRoot: signedMsg.RecentMerkleRoot,
		Signature:        signature,
	}

	// 7. Verify the signature with the correct public key.
	t.Run("Valid Signature", func(t *testing.T) {
		err := crypto.VerifyMessageSignature(protocolMsg, publicKey)
		assert.NoError(t, err, "Signature should be valid")
	})

	// 8. Test verification with an incorrect public key.
	t.Run("Invalid Signature - Wrong Key", func(t *testing.T) {
		wrongPublicKey, _, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)

		err = crypto.VerifyMessageSignature(protocolMsg, wrongPublicKey)
		assert.ErrorIs(t, err, crypto.ErrInvalidSignature, "Signature should be invalid with the wrong public key")
	})

	// 9. Test verification with a tampered message.
	t.Run("Invalid Signature - Tampered Message", func(t *testing.T) {
		tamperedProtocolMsg := &protocol.ProtocolMessage{
			PKDContext:       signedMsg.PKDContext,
			Action:           "TamperedAction", // Tampered field
			Message:          signedMsg.Message,
			RecentMerkleRoot: signedMsg.RecentMerkleRoot,
			Signature:        signature,
		}

		err := crypto.VerifyMessageSignature(tamperedProtocolMsg, publicKey)
		assert.ErrorIs(t, err, crypto.ErrInvalidSignature, "Signature should be invalid for a tampered message")
	})
}

func TestSignedMessage_CanonicalJSON(t *testing.T) {
	// 1. Create two identical message payloads but marshal them from structs with different field orders.
	// This simulates receiving JSON with different key orders.
	payload1 := struct {
		Actor     string `json:"actor"`
		Time      string `json:"time"`
		PublicKey string `json:"public-key"`
	}{
		Actor:     "test@example.com",
		Time:      "2024-05-20T12:00:00Z",
		PublicKey: "ed25519:some_public_key",
	}
	payload1JSON, err := json.Marshal(payload1)
	require.NoError(t, err)

	payload2 := struct {
		PublicKey string `json:"public-key"`
		Actor     string `json:"actor"`
		Time      string `json:"time"`
	}{
		PublicKey: "ed25519:some_public_key",
		Actor:     "test@example.com",
		Time:      "2024-05-20T12:00:00Z",
	}
	payload2JSON, err := json.Marshal(payload2)
	require.NoError(t, err)

	// Ensure the raw JSON is actually different to make the test meaningful
	require.NotEqual(t, string(payload1JSON), string(payload2JSON))

	// 2. Create two SignedMessage structs using these different raw payloads.
	signedMsg1 := protocol.SignedMessage{
		PKDContext:       "https://github.com/fedi-e2ee/public-key-directory/v1",
		Action:           "AddKey",
		Message:          payload1JSON,
		RecentMerkleRoot: "some-merkle-root",
	}

	signedMsg2 := protocol.SignedMessage{
		PKDContext:       "https://github.com/fedi-e2ee/public-key-directory/v1",
		Action:           "AddKey",
		Message:          payload2JSON,
		RecentMerkleRoot: "some-merkle-root",
	}

	// 3. Canonicalize both messages using the same process as VerifyMessageSignature.
	tempBytes1, err := json.Marshal(signedMsg1)
	require.NoError(t, err)
	canonical1, err := jcs.Transform(tempBytes1)
	require.NoError(t, err)

	tempBytes2, err := json.Marshal(signedMsg2)
	require.NoError(t, err)
	canonical2, err := jcs.Transform(tempBytes2)
	require.NoError(t, err)

	// 4. Assert that the canonical representations are identical.
	assert.Equal(t, string(canonical1), string(canonical2), "Canonical JSON output should be deterministic regardless of inner message key order")

	// 5. Also check against an expected canonical string.
	expectedCanonical := `{"!pkd-context":"https://github.com/fedi-e2ee/public-key-directory/v1","action":"AddKey","message":{"actor":"test@example.com","public-key":"ed25519:some_public_key","time":"2024-05-20T12:00:00Z"},"recent-merkle-root":"some-merkle-root"}`
	assert.Equal(t, expectedCanonical, string(canonical1))
}

func TestSignedMessage_SelfSignedAddKey(t *testing.T) {
	// 1. Generate a new Ed25519 key pair that will be used for self-signing.
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// 2. Create the AddKey message payload containing its own public key.
	addKeyMsg := protocol.AddKeyMessage{
		Actor:     "new-actor@example.com",
		Time:      "2024-05-20T13:00:00Z",
		PublicKey: crypto.EncodePublicKey(publicKey), // Self-referential public key
	}
	addKeyMsgJSON, err := json.Marshal(addKeyMsg)
	require.NoError(t, err)

	// 3. Create the message to be signed.
	signedMsg := protocol.SignedMessage{
		PKDContext:       "https://github.com/fedi-e2ee/public-key-directory/v1",
		Action:           "AddKey",
		Message:          addKeyMsgJSON,
		RecentMerkleRoot: "some-initial-root",
	}

	// 4. Canonicalize the message for signing.
	tempBytes, err := json.Marshal(signedMsg)
	require.NoError(t, err)
	signedMsgBytes, err := jcs.Transform(tempBytes)
	require.NoError(t, err)

	// 5. Sign the message with its own private key.
	signature, err := crypto.SignMessage(privateKey, signedMsgBytes)
	require.NoError(t, err)

	// 6. Create the full ProtocolMessage for verification.
	protocolMsg := &protocol.ProtocolMessage{
		PKDContext:       signedMsg.PKDContext,
		Action:           signedMsg.Action,
		Message:          signedMsg.Message,
		RecentMerkleRoot: signedMsg.RecentMerkleRoot,
		Signature:        signature,
	}

	// 7. Verify the signature. The public key for verification is the one from the message itself.
	err = crypto.VerifyMessageSignature(protocolMsg, publicKey)
	assert.NoError(t, err, "Self-signed AddKey message should be valid")
}
