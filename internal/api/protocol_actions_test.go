package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"crypto/ed25519"

	"github.com/fedi-e2ee/pkd-server-go/internal/crypto"
	dbmock "github.com/fedi-e2ee/pkd-server-go/internal/db/mock"
	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	servicemock "github.com/fedi-e2ee/pkd-server-go/internal/domain/mock"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/fedi-e2ee/pkd-server-go/internal/sigsum"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestServer_processQueryAction(t *testing.T) {
	t.Run("returns keys for actor", func(t *testing.T) {
		// setup
		repo := new(dbmock.Repository)
		repo.On("ListKeysForActor", mock.Anything, "actor-id").Return([]*domain.PublicKey{
			{
				KeyID:     "key-id-1",
				ActorID:   1,
				PublicKey: "public-key-1",
			},
			{
				KeyID:     "key-id-2",
				ActorID:   1,
				PublicKey: "public-key-2",
			},
		}, nil)
		server := &Server{
			repo: repo,
		}
		queryMsg := protocol.QueryMessage{
			Actor: "actor-id",
		}
		msgBytes, _ := json.Marshal(queryMsg)
		protoMsg := &protocol.ProtocolMessage{
			Action:  "Query",
			Message: msgBytes,
		}
		req := httptest.NewRequest(http.MethodPost, "/protocol", bytes.NewBuffer(msgBytes))
		res := httptest.NewRecorder()

		// exercise
		server.processQueryAction(res, req, protoMsg)

		// assert
		assert.Equal(t, http.StatusOK, res.Code)
		expectedJSON := `[
			{
				"id": 0,
				"actor_id": 1,
				"key_id": "key-id-1",
				"public_key": "public-key-1",
				"created_at": "0001-01-01T00:00:00Z",
				"merkle_root": "",
				"revoked_at": null,
				"revoke_root": null
			},
			{
				"id": 0,
				"actor_id": 1,
				"key_id": "key-id-2",
				"public_key": "public-key-2",
				"created_at": "0001-01-01T00:00:00Z",
				"merkle_root": "",
				"revoked_at": null,
				"revoke_root": null
			}
		]`
		assert.JSONEq(t, expectedJSON, res.Body.String())
	})
}

func TestServer_processBurnDownAction(t *testing.T) {
	t.Run("proceeds without TOTP if no secret is configured", func(t *testing.T) {
		// setup
		repo := new(dbmock.Repository)
		repo.On("GetTOTPSecret", mock.Anything, "operator-id").Return(nil, nil)

		// Create a real key pair for signing
		publicKey, privateKey, err := ed25519.GenerateKey(nil)
		assert.NoError(t, err)

		repo.On("ListKeysForActor", mock.Anything, "operator-id").Return([]*domain.PublicKey{
			{
				KeyID:     "key-id-1",
				ActorID:   1,
				PublicKey: crypto.EncodePublicKey(publicKey),
			},
		}, nil)
		sigsum := new(sigsum.MockClient)
		sigsum.On("SubmitMessage", mock.Anything, mock.Anything).Return("merkle-root", nil)
		service := new(servicemock.Service)
		service.On("ProcessBurnDown", mock.Anything, "actor-id", "merkle-root").Return(nil)
		server := &Server{
			repo:    repo,
			sigsum:  sigsum,
			service: service,
		}
		burnDownMsg := protocol.BurnDownMessage{
			Operator: "operator-id",
			Actor:    "actor-id",
		}
		msgBytes, _ := json.Marshal(burnDownMsg)
		protoMsg := &protocol.ProtocolMessage{
			Action:  "BurnDown",
			Message: msgBytes,
		}

		// Create the canonical form for signing, as per the specification.
		signedMsg := protocol.SignedMessage{
			PKDContext: protoMsg.PKDContext,
			Action:     protoMsg.Action,
			Message:    protoMsg.Message,
		}
		signedMsgBytes, err := json.Marshal(signedMsg)
		assert.NoError(t, err)

		signature, err := crypto.SignMessage(privateKey, signedMsgBytes)
		assert.NoError(t, err)
		protoMsg.Signature = signature

		req := httptest.NewRequest(http.MethodPost, "/protocol", bytes.NewBuffer(msgBytes))
		res := httptest.NewRecorder()

		// exercise
		server.processBurnDownAction(res, req, protoMsg)

		// assert
		assert.Equal(t, http.StatusOK, res.Code)
	})
}
