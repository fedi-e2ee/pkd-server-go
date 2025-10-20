package protocol_test

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/fedi-e2ee/pkd-server-go/internal/crypto"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/gowebpki/jcs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This test case is not meant for automated validation, but rather to
// provide a concrete, deterministic example of a signed message that can be
// used for interoperability testing with client implementations.
func TestGenerateAddKeySignedMessageExample(t *testing.T) {
	// 1. Use a hardcoded Ed25519 private key for deterministic output.
	// This key was generated once and saved.
	const hardcodedPrivateKey = "sN4vhvYhQBUyuVbVDud_hHliEnHL9VaMcLMB5eFlmazMHV78mMcZVilGbVjQP-cNkb52yPiGDVIGDTxX9Yhycg"
	const expectedPublicKey = "ed25519:zB1e_JjHGVYpRm1Y0D_nDZG-dsj4hg1SBg08V_WIcnI"
	const expectedSignature = "fWKOKkJgxVe7MhjajfI2OGUbUsHlhFeWN3Qqyq1YTxhBpPKv-y-M1YdsNjyMNZ_y-3Pq7vkb91zevG4HJLy3Bg"

	privateKey, err := crypto.DecodeSecretKey(hardcodedPrivateKey)
	require.NoError(t, err)

	// Derive the public key from the private key.
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// 2. Prepare the inner "AddKey" message with a fixed timestamp.
	addKeyMsg := protocol.AddKeyMessage{
		Actor:     "test@example.com",
		Time:      "2025-10-20T13:23:02Z",
		PublicKey: crypto.EncodePublicKey(publicKey),
	}
	addKeyMsgBytes, err := json.Marshal(addKeyMsg)
	require.NoError(t, err)

	// 3. Construct the "SignedMessage" which is the data that gets signed.
	signedMsg := protocol.SignedMessage{
		PKDContext:       "https://github.com/fedi-e2ee/public-key-directory/v1",
		Action:           "AddKey",
		Message:          addKeyMsgBytes,
		RecentMerkleRoot: "b3daa77b4c048591811a4e273da6a77b42000a6a43b2f153a5316df016f46132",
	}
	tempBytes, err := json.Marshal(signedMsg)
	require.NoError(t, err)
	signedMsgBytes, err := jcs.Transform(tempBytes)
	require.NoError(t, err)

	// 4. Sign the canonical JSON of the "SignedMessage".
	signature, err := crypto.SignMessage(privateKey, signedMsgBytes)
	require.NoError(t, err)

	// 5. Assemble the final "ProtocolMessage".
	protocolMsg := protocol.ProtocolMessage{
		PKDContext:       signedMsg.PKDContext,
		Action:           signedMsg.Action,
		Message:          signedMsg.Message,
		RecentMerkleRoot: signedMsg.RecentMerkleRoot,
		Signature:        signature,
	}

	// 6. Output all the components for easy use in other software.
	fmt.Println("--- Generated Test Case: AddKey Signed Message ---")
	fmt.Printf("Signing Public Key: %s\n", crypto.EncodePublicKey(publicKey))
	fmt.Printf("Signing Private Key: %s\n", crypto.EncodePrivateKey(privateKey))
	fmt.Println("--- Protocol Message ---")
	protocolMsgJSON, err := json.MarshalIndent(protocolMsg, "", "  ")
	require.NoError(t, err)
	fmt.Println(string(protocolMsgJSON))

	// 7. Verification step to ensure the generated message is valid and deterministic.
	assert.Equal(t, expectedPublicKey, crypto.EncodePublicKey(publicKey), "Public key should match the expected value")
	assert.Equal(t, expectedSignature, signature, "Signature should match the expected value")

	decodedPublicKey, err := crypto.DecodePublicKey(crypto.EncodePublicKey(publicKey))
	require.NoError(t, err)
	err = crypto.VerifyMessageSignature(&protocolMsg, decodedPublicKey)
	assert.NoError(t, err, "Signature verification should succeed")
}
