package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"errors"

	"github.com/fedi-e2ee/pkd-server-go/internal/crypto"
	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/fedi-e2ee/pkd-server-go/internal/util"
)

// TriggerCheckpointRequest is the request body for the admin endpoint that
// manually triggers sending a checkpoint to a peer.
type TriggerCheckpointRequest struct {
	ToDirectory string `json:"to-directory"`
}

// CryptoShredRequest is the request body for the admin endpoint that
// triggers crypto-shredding for a specific user.
type CryptoShredRequest struct {
	ActorID string `json:"actor-id"`
}

// handleCryptoShred handles an administrative request to perform crypto-shredding for a given actor.
//
// This functionality exists to facilitate "Right To Be Forgotten" requests, as required by some data privacy
// legislation. It calls the domain service to erase the symmetric keys associated with an actor's historical records,
// rendering them unreadable.
//
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#message-attribute-shreddability
func (s *Server) handleCryptoShred(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req CryptoShredRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			s.respondWithError(w, http.StatusRequestEntityTooLarge, "Request body too large")
			return
		}
		s.respondWithError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if req.ActorID == "" {
		s.respondWithError(w, http.StatusBadRequest, "Missing actor-id in request")
		return
	}

	// Call the service layer to perform the crypto-shredding logic.
	if err = s.service.CryptoShred(ctx, req.ActorID); err != nil && !errors.Is(err, domain.ErrActorNotFound) {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to crypto-shred actor: "+err.Error())
		return
	}

	s.respondWithJSON(w, http.StatusOK, map[string]string{
		"status":   "crypto-shredding completed",
		"actor-id": req.ActorID,
	})
}

// handleTriggerCheckpoint handles an administrative request to send a Checkpoint message to a peer PKD instance.
//
// Checkpoints implement a type of active gossip.
//
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#active-gossip-checkpoints
func (s *Server) handleTriggerCheckpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req TriggerCheckpointRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			s.respondWithError(w, http.StatusRequestEntityTooLarge, "Request body too large")
			return
		}
		s.respondWithError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if req.ToDirectory == "" {
		s.respondWithError(w, http.StatusBadRequest, "Missing to-directory in request")
		return
	}

	// Prevent SSRF by validating the URL of the directory
	validatedURL, err := util.ValidateURL(req.ToDirectory, s.config.Test.AllowPrivateIPs)
	if err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid to-directory URL: "+err.Error())
		return
	}

	// 1. Get the latest Merkle root from our own server's transparency log.
	latestRoot, err := s.repo.GetLatestMerkleRoot(ctx)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to get latest merkle root: "+err.Error())
		return
	}
	if latestRoot == "" {
		s.respondWithError(w, http.StatusBadRequest, "No messages on server to create a checkpoint from")
		return
	}

	// 2. Create the Checkpoint message payload.
	checkpointMsg := protocol.CheckpointMessage{
		Time:          time.Now().UTC().Format(time.RFC3339),
		FromDirectory: fmt.Sprintf("http://%s:%d", s.config.Server.Host, s.config.Server.Port),
		FromRoot:      latestRoot,
		ToDirectory:   req.ToDirectory,
		// ToValidatedRoot is intentionally left blank here. The specification states
		// it is filled in by the recipient upon validation.
	}
	checkpointMsgBytes, err := json.Marshal(checkpointMsg)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to marshal checkpoint message")
		return
	}

	// 3. Create the top-level ProtocolMessage and sign it with this server's private key.
	protoMsg := protocol.ProtocolMessage{
		PKDContext: "https://github.com/fedi-e2ee/public-key-directory/v1",
		Action:     "Checkpoint",
		Message:    checkpointMsgBytes,
	}

	privateKeyBytes, err := base64.RawURLEncoding.DecodeString(s.config.Server.PrivateKey)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to decode server private key")
		return
	}
	privateKey := ed25519.PrivateKey(privateKeyBytes)

	// Create the canonical form for signing, as per the specification.
	signedMsg := protocol.SignedMessage{
		PKDContext: protoMsg.PKDContext,
		Action:     protoMsg.Action,
		Message:    protoMsg.Message,
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to marshal signed message for signing")
		return
	}

	signature, err := crypto.SignMessage(privateKey, signedMsgBytes)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to sign message")
		return
	}
	protoMsg.Signature = signature

	// 4. Send the complete, signed message to the target directory's protocol endpoint.
	finalMsgBytes, err := json.Marshal(protoMsg)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to marshal final protocol message")
		return
	}

	resp, err := http.Post(validatedURL.String()+"/protocol", "application/json", bytes.NewBuffer(finalMsgBytes))
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to send checkpoint to peer: "+err.Error())
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		s.respondWithError(w, http.StatusBadGateway, fmt.Sprintf("Peer server responded with status %d", resp.StatusCode))
		return
	}

	s.respondWithJSON(w, http.StatusOK, map[string]string{
		"status": "checkpoint sent successfully",
		"to":     req.ToDirectory,
	})
}
