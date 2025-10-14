package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/fedi-e2ee/pkd-server-go/internal/crypto"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/fedi-e2ee/pkd-server-go/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMoveIdentity_Success(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti.Teardown()

	// --- Setup: Create an actor with one key ---
	oldActorID := "https://social.example/users/pre-move-user"

	// Add the initial key
	keyID, _, privKey, err := testutil.AddSampleKey(t, ti, oldActorID, nil, nil)
	require.NoError(t, err)
	require.NotEmpty(t, keyID)

	// --- Test: Move the identity ---
	newActorID := "https://social.example/users/post-move-user"
	moveMsg := protocol.MoveIdentityMessage{
		OldActor: oldActorID,
		NewActor: newActorID,
		Time:     fmt.Sprintf("%d", time.Now().Unix()),
	}
	moveMsgBytes, err := json.Marshal(moveMsg)
	require.NoError(t, err)

	protocolMsg := &protocol.ProtocolMessage{
		PKDContext:       "https://github.com/fedi-e2ee/public-key-directory/v1",
		Action:           "MoveIdentity",
		Message:          moveMsgBytes,
		RecentMerkleRoot: "pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}

	// Sign with the original key
	signedMsg := protocol.SignedMessage{
		PKDContext:       protocolMsg.PKDContext,
		Action:           protocolMsg.Action,
		Message:          protocolMsg.Message,
		RecentMerkleRoot: protocolMsg.RecentMerkleRoot,
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	require.NoError(t, err)
	signature, err := crypto.SignMessage(privKey, signedMsgBytes)
	require.NoError(t, err)
	protocolMsg.Signature = signature

	reqBody, err := json.Marshal(protocolMsg)
	require.NoError(t, err)

	resp, err := http.Post(ti.Server.URL+"/protocol", "application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert the HTTP response
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected status OK for MoveIdentity")

	// --- Verification ---
	// 1. Old actor should not exist
	oldActor, err := ti.Repo.FindActorByActorID(ti.Ctx, oldActorID)
	require.NoError(t, err)
	assert.Nil(t, oldActor, "Old actor ID should no longer exist")

	// 2. New actor should exist
	newActor, err := ti.Repo.FindActorByActorID(ti.Ctx, newActorID)
	require.NoError(t, err)
	require.NotNil(t, newActor, "New actor ID should exist")
	assert.Equal(t, newActorID, newActor.ActorID)

	// 3. The key should now be associated with the new actor
	keys, err := ti.Repo.ListKeysForActor(ti.Ctx, newActorID)
	require.NoError(t, err)
	require.Len(t, keys, 1, "Expected one key to be associated with the new actor ID")
	assert.Equal(t, keyID, keys[0].KeyID, "The key ID should remain the same")
}
