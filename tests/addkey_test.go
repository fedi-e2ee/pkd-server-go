package tests

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/fedi-e2ee/pkd-server-go/internal/crypto"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/fedi-e2ee/pkd-server-go/internal/testutil"
	"github.com/gowebpki/jcs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddKey_FirstKeyForNewActor(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti.Teardown()

	// 1. Generate a key pair for the new user
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "Failed to generate ed25519 key pair")

	// 2. Construct the AddKey protocol message
	actorID := "https://social.example/users/alice"
	encodedPubKey := fmt.Sprintf("ed25519:%s", base64.RawURLEncoding.EncodeToString(pubKey))

	addKeyMsg := protocol.AddKeyMessage{
		Actor:     actorID,
		Time:      fmt.Sprintf("%d", time.Now().Unix()),
		PublicKey: encodedPubKey,
	}

	addKeyMsgBytes, err := json.Marshal(addKeyMsg)
	require.NoError(t, err)

	// This is a self-signed message for the first key
	protocolMsg := &protocol.ProtocolMessage{
		PKDContext:       "https://github.com/fedi-e2ee/public-key-directory/v1",
		Action:           "AddKey",
		Message:          addKeyMsgBytes,
		RecentMerkleRoot: "pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Initial root
	}

	// Sign the message
	signedMsg := protocol.SignedMessage{
		PKDContext:       protocolMsg.PKDContext,
		Action:           protocolMsg.Action,
		Message:          protocolMsg.Message,
		RecentMerkleRoot: protocolMsg.RecentMerkleRoot,
	}
	tempBytes, err := json.Marshal(signedMsg)
	require.NoError(t, err)
	signedMsgBytes, err := jcs.Transform(tempBytes)
	require.NoError(t, err)
	signature, err := crypto.SignMessage(privKey, signedMsgBytes)
	require.NoError(t, err)
	protocolMsg.Signature = signature

	// 3. Send the message to the server
	reqBody, err := json.Marshal(protocolMsg)
	require.NoError(t, err)

	resp, err := http.Post(ti.Server.URL+"/protocol", "application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// 4. Assert the HTTP response
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected status OK")

	var respBody map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	require.NoError(t, err)
	assert.Contains(t, respBody, "key_id", "Response should contain a key_id")

	// 5. Verify the database state
	// Check that the actor was created
	actor, err := ti.Repo.FindActorByActorID(ti.Ctx, actorID)
	require.NoError(t, err)
	require.NotNil(t, actor, "Actor should have been created in the database")
	assert.Equal(t, actorID, actor.ActorID)
	assert.False(t, actor.IsFireproof, "New actor should not be fireproof")

	// Check that the key was added
	keys, err := ti.Repo.ListKeysForActor(ti.Ctx, actorID)
	require.NoError(t, err)
	require.Len(t, keys, 1, "Expected one key to be added for the actor")

	addedKey := keys[0]
	assert.Equal(t, encodedPubKey, addedKey.PublicKey)
	assert.Equal(t, respBody["key_id"], addedKey.KeyID) // Ensure the returned key_id matches the one in DB
	assert.Nil(t, addedKey.RevokedAt, "The new key should not be revoked")
}
