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
	"github.com/gowebpki/jcs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRevokeKey_Success(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti.Teardown()

	// --- Setup: Create an actor with two keys ---
	actorID := "https://social.example/users/revoker"
	keyID1, pubKey1, privKey1, err := testutil.AddSampleKey(t, ti, actorID, nil, nil)
	require.NoError(t, err)
	keyID2, _, privKey2, err := testutil.AddSampleKey(t, ti, actorID, privKey1, nil)
	require.NoError(t, err)

	// --- Test: Revoke the first key using the second key ---
	revokeMsg := protocol.RevokeKeyMessage{
		Actor:     actorID,
		PublicKey: crypto.EncodePublicKey(pubKey1),
		Time:      fmt.Sprintf("%d", time.Now().Unix()),
	}
	revokeMsgBytes, err := json.Marshal(revokeMsg)
	require.NoError(t, err)

	protocolMsg := &protocol.ProtocolMessage{
		PKDContext: "https://github.com/fedi-e2ee/public-key-directory/v1",
		Action:     "RevokeKey",
		Message:    revokeMsgBytes,
	}

	// Sign with the second, still-valid key
	signedMsg := protocol.SignedMessage{
		PKDContext: protocolMsg.PKDContext,
		Action:     protocolMsg.Action,
		Message:    protocolMsg.Message,
	}
	tempBytes, err := json.Marshal(signedMsg)
	require.NoError(t, err)
	signedMsgBytes, err := jcs.Transform(tempBytes)
	require.NoError(t, err)
	signature, err := crypto.SignMessage(privKey2, signedMsgBytes)
	require.NoError(t, err)
	protocolMsg.Signature = signature

	reqBody, err := json.Marshal(protocolMsg)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", ti.Server.URL+"/protocol", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert the HTTP response
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected status OK for RevokeKey")

	// --- Verification ---
	// Key 1 should be revoked
	key1, err := ti.Repo.FindKeyByKeyID(ti.Ctx, keyID1)
	require.NoError(t, err)
	assert.NotNil(t, key1.RevokedAt, "Key 1 should be revoked")

	// Key 2 should not be revoked
	key2, err := ti.Repo.FindKeyByKeyID(ti.Ctx, keyID2)
	require.NoError(t, err)
	assert.Nil(t, key2.RevokedAt, "Key 2 should not be revoked")
}
