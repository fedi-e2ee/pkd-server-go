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
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFireproof_And_UndoFireproof(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti.Teardown()

	// --- Setup: Create an actor with one key ---
	actorID := "https://social.example/users/fireproofer"
	_, _, privKey, err := testutil.AddSampleKey(t, ti, actorID, nil, nil)
	require.NoError(t, err)

	// --- Test: Fireproof ---
	fireproofMsg := protocol.FireproofMessage{
		Actor: actorID,
		Time:  fmt.Sprintf("%d", time.Now().Unix()),
	}
	fireproofMsgBytes, err := json.Marshal(fireproofMsg)
	require.NoError(t, err)
	protocolMsg := &protocol.ProtocolMessage{
		PKDContext: "https://github.com/fedi-e2ee/public-key-directory/v1",
		Action:     "Fireproof",
		Message:    fireproofMsgBytes,
	}
	signedMsg := protocol.SignedMessage{
		PKDContext: protocolMsg.PKDContext,
		Action:     protocolMsg.Action,
		Message:    protocolMsg.Message,
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
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify fireproof status is true
	isFireproof, err := ti.Repo.IsFireproof(ti.Ctx, actorID)
	require.NoError(t, err)
	assert.True(t, isFireproof, "Actor should be fireproofed")

	// --- Test: Undo Fireproof ---
	undoMsg := protocol.UndoFireproofMessage{
		Actor: actorID,
		Time:  fmt.Sprintf("%d", time.Now().Unix()),
	}
	undoMsgBytes, err := json.Marshal(undoMsg)
	require.NoError(t, err)
	protocolMsg.Action = "UndoFireproof"
	protocolMsg.Message = undoMsgBytes
	signedMsg = protocol.SignedMessage{
		PKDContext: protocolMsg.PKDContext,
		Action:     protocolMsg.Action,
		Message:    protocolMsg.Message,
	}
	signedMsgBytes, err = json.Marshal(signedMsg)
	require.NoError(t, err)
	signature, err = crypto.SignMessage(privKey, signedMsgBytes)
	require.NoError(t, err)
	protocolMsg.Signature = signature
	reqBody, err = json.Marshal(protocolMsg)
	require.NoError(t, err)
	resp, err = http.Post(ti.Server.URL+"/protocol", "application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify fireproof status is false
	isFireproof, err = ti.Repo.IsFireproof(ti.Ctx, actorID)
	require.NoError(t, err)
	assert.False(t, isFireproof, "Actor should not be fireproofed")
}

func TestAddAuxData_And_RevokeAuxData(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti.Teardown()

	// --- Setup: Create an actor with one key ---
	actorID := "https://social.example/users/aux-user"
	_, _, privKey, err := testutil.AddSampleKey(t, ti, actorID, nil, nil)
	require.NoError(t, err)

	// --- Test: AddAuxData ---
	addAuxMsg := protocol.AddAuxDataMessage{
		Actor:   actorID,
		AuxType: "profile",
		AuxData: "{\"name\":\"Test User\"}",
		Time:    fmt.Sprintf("%d", time.Now().Unix()),
	}
	addAuxMsgBytes, err := json.Marshal(addAuxMsg)
	require.NoError(t, err)
	protocolMsg := &protocol.ProtocolMessage{
		PKDContext: "https://github.com/fedi-e2ee/public-key-directory/v1",
		Action:     "AddAuxData",
		Message:    addAuxMsgBytes,
	}
	signedMsg := protocol.SignedMessage{
		PKDContext: protocolMsg.PKDContext,
		Action:     protocolMsg.Action,
		Message:    protocolMsg.Message,
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
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify AuxData was added
	var addRespBody map[string]string
	err = json.NewDecoder(resp.Body).Decode(&addRespBody)
	require.NoError(t, err)
	auxID := addRespBody["aux_id"]
	require.NotEmpty(t, auxID)
	auxData, err := ti.Repo.FindAuxDataByAuxID(ti.Ctx, auxID)
	require.NoError(t, err)
	require.NotNil(t, auxData)
	assert.Equal(t, "profile", auxData.AuxType)

	// --- Test: RevokeAuxData ---
	revokeAuxMsg := protocol.RevokeAuxDataMessage{
		Actor: actorID,
		AuxID: auxID,
		Time:  fmt.Sprintf("%d", time.Now().Unix()),
	}
	revokeAuxMsgBytes, err := json.Marshal(revokeAuxMsg)
	require.NoError(t, err)
	protocolMsg.Action = "RevokeAuxData"
	protocolMsg.Message = revokeAuxMsgBytes
	signedMsg = protocol.SignedMessage{
		PKDContext: protocolMsg.PKDContext,
		Action:     protocolMsg.Action,
		Message:    protocolMsg.Message,
	}
	signedMsgBytes, err = json.Marshal(signedMsg)
	require.NoError(t, err)
	signature, err = crypto.SignMessage(privKey, signedMsgBytes)
	require.NoError(t, err)
	protocolMsg.Signature = signature
	reqBody, err = json.Marshal(protocolMsg)
	require.NoError(t, err)
	resp, err = http.Post(ti.Server.URL+"/protocol", "application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify AuxData was revoked
	revokedAux, err := ti.Repo.FindAuxDataByAuxID(ti.Ctx, auxID)
	require.NoError(t, err)
	assert.NotNil(t, revokedAux.RevokedAt, "Aux data should be revoked")
}

func TestBurnDown_Success(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti.Teardown()

	// --- Setup ---
	// 1. Create actor with a key
	actorID := "https://social.example/users/burn-user"
	_, _, _, err = testutil.AddSampleKey(t, ti, actorID, nil, nil)
	require.NoError(t, err)

	// 2. Enroll TOTP for the operator
	operator := "https://social.example"
	_, _, operatorPrivKey, err := testutil.AddSampleKey(t, ti, operator, nil, nil)
	require.NoError(t, err)
	totpSecret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      operator,
		AccountName: "pkd-server-test",
	})
	require.NoError(t, err)
	encryptedSecret, err := crypto.EncryptWithHPKE(ti.PubKey, []byte(totpSecret.Secret()))
	require.NoError(t, err)
	err = ti.Repo.StoreTOTPSecret(ti.Ctx, operator, encryptedSecret)
	require.NoError(t, err)

	// 3. Generate a valid passcode
	passcode, err := totp.GenerateCode(totpSecret.Secret(), time.Now())
	require.NoError(t, err)

	// --- Test: BurnDown ---
	burnMsg := protocol.BurnDownMessage{
		Actor:    actorID,
		Operator: operator,
		Time:     fmt.Sprintf("%d", time.Now().Unix()),
	}
	burnMsgBytes, err := json.Marshal(burnMsg)
	require.NoError(t, err)
	protocolMsg := &protocol.ProtocolMessage{
		PKDContext: "https://github.com/fedi-e2ee/public-key-directory/v1",
		Action:     "BurnDown",
		Message:    burnMsgBytes,
		OTP:        passcode,
	}
	signedMsg := protocol.SignedMessage{
		PKDContext: protocolMsg.PKDContext,
		Action:     protocolMsg.Action,
		Message:    protocolMsg.Message,
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	require.NoError(t, err)
	signature, err := crypto.SignMessage(operatorPrivKey, signedMsgBytes)
	require.NoError(t, err)
	protocolMsg.Signature = signature
	reqBody, err := json.Marshal(protocolMsg)
	require.NoError(t, err)
	resp, err := http.Post(ti.Server.URL+"/protocol", "application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// --- Verification ---
	// All keys should be revoked
	keys, err := ti.Repo.ListKeysForActor(ti.Ctx, actorID)
	require.NoError(t, err)
	assert.Empty(t, keys, "All keys for the actor should be revoked")
}

func TestBurnDown_CryptoShredding(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti.Teardown()

	// --- Setup ---
	// 1. Create actor with a key and a symmetric key
	actorID := "https://social.example/users/crypto-shred-user"

	symKeys := map[string]string{
		"profile_name": "test-key-base64",
	}
	keyID, _, _, err := testutil.AddSampleKey(t, ti, actorID, nil, symKeys)
	require.NoError(t, err)

	// 2. Verify the symmetric key was stored
	keyInfo, err := ti.Repo.FindKeyByKeyID(ti.Ctx, keyID)
	require.NoError(t, err)
	merkleRoot := keyInfo.MerkleRoot
	storedKeys, err := ti.Repo.FindSymmetricKeysByMessageHash(ti.Ctx, merkleRoot)
	require.NoError(t, err)
	require.Len(t, storedKeys, 1, "Expected one symmetric key to be stored")
	assert.Equal(t, "profile_name", storedKeys[0].Attribute)

	// 3. Enroll TOTP for the operator
	operator := "https://social.example"
	_, _, operatorPrivKey, err := testutil.AddSampleKey(t, ti, operator, nil, nil)
	require.NoError(t, err)
	totpSecret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      operator,
		AccountName: "pkd-server-test-shred",
	})
	require.NoError(t, err)
	encryptedSecret, err := crypto.EncryptWithHPKE(ti.PubKey, []byte(totpSecret.Secret()))
	require.NoError(t, err)
	err = ti.Repo.StoreTOTPSecret(ti.Ctx, operator, encryptedSecret)
	require.NoError(t, err)

	// 4. Generate a valid passcode
	passcode, err := totp.GenerateCode(totpSecret.Secret(), time.Now())
	require.NoError(t, err)

	// --- Test: BurnDown ---
	burnMsg := protocol.BurnDownMessage{
		Actor:    actorID,
		Operator: operator,
		Time:     fmt.Sprintf("%d", time.Now().Unix()),
	}
	burnMsgBytes, err := json.Marshal(burnMsg)
	require.NoError(t, err)
	protocolMsg := &protocol.ProtocolMessage{
		PKDContext: "https://github.com/fedi-e2ee/public-key-directory/v1",
		Action:     "BurnDown",
		Message:    burnMsgBytes,
		OTP:        passcode,
	}
	signedMsg := protocol.SignedMessage{
		PKDContext: protocolMsg.PKDContext,
		Action:     protocolMsg.Action,
		Message:    protocolMsg.Message,
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	require.NoError(t, err)
	signature, err := crypto.SignMessage(operatorPrivKey, signedMsgBytes)
	require.NoError(t, err)
	protocolMsg.Signature = signature
	reqBody, err := json.Marshal(protocolMsg)
	require.NoError(t, err)
	resp, err := http.Post(ti.Server.URL+"/protocol", "application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// --- Verification ---
	// The symmetric key should now be deleted
	shreddedKeys, err := ti.Repo.FindSymmetricKeysByMessageHash(ti.Ctx, merkleRoot)
	require.NoError(t, err)
	assert.Empty(t, shreddedKeys, "Symmetric key should have been deleted by BurnDown")
}
