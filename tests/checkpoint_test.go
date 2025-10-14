package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fedi-e2ee/pkd-server-go/internal/api"
	"github.com/fedi-e2ee/pkd-server-go/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckpointIntegration(t *testing.T) {
	// --- Server 1 Setup ---
	ti1, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti1.Teardown()

	// --- Server 2 Setup ---
	ti2, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti2.Teardown()

	// Add server 1 to server 2's peers
	server1URL := ti1.Server.URL
	ti2.Config.Peers[server1URL] = ti1.GetPeerConfig()

	// --- Test Flow ---
	// 1. Add a key to Server 1 to have a merkle root
	_, _, _, err = testutil.AddSampleKey(t, ti1, "user1@server1", nil, nil)
	require.NoError(t, err)

	// This is a bit of a hack to make sure the message is processed before we try to create a checkpoint
	time.Sleep(100 * time.Millisecond)

	// 2. Server 1 triggers a checkpoint to Server 2
	checkpointReq := api.TriggerCheckpointRequest{
		ToDirectory: ti2.Server.URL,
	}
	reqBody, _ := json.Marshal(checkpointReq)
	req := httptest.NewRequest("POST", "/admin/checkpoint", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	accessToken, _, err := ti1.TokenService.NewPair()
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp := httptest.NewRecorder()
	ti1.Router.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code, "Expected server 1 to successfully send checkpoint")

	var checkpointResp map[string]string
	err = json.Unmarshal(resp.Body.Bytes(), &checkpointResp)
	require.NoError(t, err)
	assert.Equal(t, "checkpoint sent successfully", checkpointResp["status"])

	// 3. Verify the checkpoint message was stored on Server 2
	var messageCount int
	var query string
	if ti2.DB.DriverName() == "sqlite3" {
		query = "SELECT COUNT(*) FROM message_logs WHERE json_extract(decrypted_message, '$.action') = 'Checkpoint'"
	} else {
		query = "SELECT COUNT(*) FROM message_logs WHERE decrypted_message->>'action' = 'Checkpoint'"
	}
	err = ti2.DB.Get(&messageCount, query)
	require.NoError(t, err)
	assert.Equal(t, 1, messageCount, "Expected one checkpoint message to be logged on server 2")
}

// TestCheckpoint_NoNewMessages tests the scenario where a checkpoint is triggered
// but there are no new messages to checkpoint. This covers a mutation
// identified by go-gremlins.
func TestCheckpoint_NoNewMessages(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti.Teardown()

	checkpointReq := api.TriggerCheckpointRequest{
		ToDirectory: "http://dummy-peer",
	}
	reqBody, _ := json.Marshal(checkpointReq)
	req := httptest.NewRequest("POST", "/admin/checkpoint", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	accessToken, _, err := ti.TokenService.NewPair()
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp := httptest.NewRecorder()
	ti.Router.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "No messages on server to create a checkpoint from")
}

func TestCryptoShred(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti.Teardown()

	// 1. Add some keys for a user
	username := "shred_me@example.com"
	key1, _, priv1, err := testutil.AddSampleKey(t, ti, username, nil, nil)
	require.NoError(t, err)
	_, _, _, err = testutil.AddSampleKey(t, ti, username, priv1, nil)
	require.NoError(t, err)

	// 2. Trigger crypto-shredding
	shredReq := api.CryptoShredRequest{
		ActorID: username,
	}
	reqBody, _ := json.Marshal(shredReq)
	req := httptest.NewRequest("POST", "/admin/crypto-shred", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	accessToken, _, err := ti.TokenService.NewPair()
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp := httptest.NewRecorder()
	ti.Router.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)

	// 3. Verify keys are revoked
	keys, err := ti.Repo.ListKeysForActor(ti.Ctx, username)
	require.NoError(t, err)
	assert.Empty(t, keys, "Expected all keys for the user to be revoked")

	// 4. Verify symmetric keys are deleted
	// We need the merkle root from the AddKey operation to find the symmetric key
	keyInfo, err := ti.Repo.FindKeyByKeyID(ti.Ctx, key1)
	require.NoError(t, err)
	require.NotNil(t, keyInfo)

	symKeys, err := ti.Repo.FindSymmetricKeysByMessageHash(ti.Ctx, keyInfo.MerkleRoot)
	require.NoError(t, err)
	assert.Empty(t, symKeys, "Expected symmetric keys to be deleted")
}

// TestCryptoShred_ActorNotFound tests the scenario where a crypto-shredding
// is triggered for a non-existent actor. This covers a mutation identified
// by go-gremlins.
func TestCryptoShred_ActorNotFound(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti.Teardown()

	shredReq := api.CryptoShredRequest{
		ActorID: "nonexistent@example.com",
	}
	reqBody, _ := json.Marshal(shredReq)
	req := httptest.NewRequest("POST", "/admin/crypto-shred", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	accessToken, _, err := ti.TokenService.NewPair()
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp := httptest.NewRecorder()
	ti.Router.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "crypto-shredding completed")
}
