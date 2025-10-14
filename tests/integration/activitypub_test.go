package integration_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pkd_crypto "github.com/fedi-e2ee/pkd-server-go/internal/crypto"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/fedi-e2ee/pkd-server-go/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMockFediverseServer sets up a mock ActivityPub server that serves an actor document.
// It returns the server, and the actor's public and private keys.
func newMockFediverseServer(t *testing.T) (*httptest.Server, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "failed to generate key pair")

	actor := map[string]interface{}{
		"@context": "https://www.w3.org/ns/activitystreams",
		"id":       "",
		"type":     "Person",
		"inbox":    "",
		"publicKey": map[string]interface{}{
			"id":           "",
			"owner":        "",
			"publicKeyPem": pkd_crypto.EncodePublicKey(pubKey),
		},
	}

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actorID := server.URL + "/users/test"
		actor["id"] = actorID
		actor["inbox"] = server.URL + "/inbox"
		publicKey := actor["publicKey"].(map[string]interface{})
		publicKey["id"] = actorID + "#main-key"
		publicKey["owner"] = actorID

		w.Header().Set("Content-Type", "application/activity+json")
		err := json.NewEncoder(w).Encode(actor)
		require.NoError(t, err, "failed to encode actor in mock server")
	}))

	t.Cleanup(func() {
		server.Close()
	})

	return server, pubKey, privKey
}

func TestActivityPubUnsignedRequestFails(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err, "failed to create test instance")
	defer ti.Teardown()

	mockFediverse, actorPubKey, _ := newMockFediverseServer(t)
	defer mockFediverse.Close()

	_, dummyPrivKey, _ := ed25519.GenerateKey(rand.Reader)

	addKeyMsg := protocol.AddKeyMessage{
		Actor:     mockFediverse.URL + "/users/test",
		Time:      time.Now().UTC().Format(time.RFC3339),
		PublicKey: pkd_crypto.EncodePublicKey(actorPubKey),
	}
	addKeyMsgBytes, err := json.Marshal(addKeyMsg)
	require.NoError(t, err)

	signedMsg := protocol.SignedMessage{
		PKDContext: "https://github.com/fedi-e2ee/public-key-directory/v1",
		Action:     "AddKey",
		Message:    addKeyMsgBytes,
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	require.NoError(t, err)

	signature, err := pkd_crypto.SignMessage(dummyPrivKey, signedMsgBytes)
	require.NoError(t, err)

	protoMsg := protocol.ProtocolMessage{
		PKDContext:    signedMsg.PKDContext,
		Action:        signedMsg.Action,
		Message:       signedMsg.Message,
		Signature:     signature,
		SymmetricKeys: nil,
	}
	protoMsgBytes, err := json.Marshal(protoMsg)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/protocol", bytes.NewReader(protoMsgBytes))
	req.Header.Set("Content-Type", "application/activity+json")
	rec := httptest.NewRecorder()
	ti.Router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "expected unauthorized for unsigned request")
}

func TestActivityPubSignedRequestSucceeds(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err, "failed to create test instance")
	defer ti.Teardown()

	mockFediverse, actorPubKey, actorPrivKey := newMockFediverseServer(t)
	defer mockFediverse.Close()

	addKeyMsg := protocol.AddKeyMessage{
		Actor:     mockFediverse.URL + "/users/test",
		Time:      time.Now().UTC().Format(time.RFC3339),
		PublicKey: pkd_crypto.EncodePublicKey(actorPubKey),
	}
	addKeyMsgBytes, err := json.Marshal(addKeyMsg)
	require.NoError(t, err)
	signedMsg := protocol.SignedMessage{
		PKDContext: "https://github.com/fedi-e2ee/public-key-directory/v1",
		Action:     "AddKey",
		Message:    addKeyMsgBytes,
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	require.NoError(t, err)
	innerSignature, err := pkd_crypto.SignMessage(actorPrivKey, signedMsgBytes)
	require.NoError(t, err)
	protoMsg := protocol.ProtocolMessage{
		PKDContext:    signedMsg.PKDContext,
		Action:        signedMsg.Action,
		Message:       signedMsg.Message,
		Signature:     innerSignature,
		SymmetricKeys: nil,
	}
	protoMsgBytes, err := json.Marshal(protoMsg)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/protocol", bytes.NewReader(protoMsgBytes))
	req.Header.Set("Content-Type", "application/activity+json")
	date := time.Now().UTC().Format(http.TimeFormat)
	req.Header.Set("Date", date)
	req.Header.Set("Host", req.URL.Host)

	digest := sha256.Sum256(protoMsgBytes)
	digestHeader := "SHA-256=" + base64.StdEncoding.EncodeToString(digest[:])
	req.Header.Set("Digest", digestHeader)

	signingString := fmt.Sprintf(
		"(request-target): post /protocol\ndate: %s\nhost: %s\ndigest: %s",
		date,
		req.URL.Host,
		digestHeader,
	)
	httpSignature, err := actorPrivKey.Sign(rand.Reader, []byte(signingString), crypto.Hash(0))
	require.NoError(t, err)

	signatureB64 := base64.StdEncoding.EncodeToString(httpSignature)
	keyID := mockFediverse.URL + "/users/test"
	headers := "(request-target) date host digest"
	signatureHeader := fmt.Sprintf(`keyId="%s",headers="%s",signature="%s"`, keyID, headers, signatureB64)
	req.Header.Set("Signature", signatureHeader)

	rec := httptest.NewRecorder()
	ti.Router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "expected OK for signed request. Body: %s", rec.Body.String())
}
