package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/cloudflare/circl/kem"
	"github.com/fedi-e2ee/pkd-server-go/internal/crypto"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
)

// processAddKeyAction handles the "AddKey" protocol message. It validates the
// signature and, if valid, submits the message to SigSum and the database.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addkey-validation-steps
func (s *Server) processAddKeyAction(w http.ResponseWriter, r *http.Request, msg *protocol.ProtocolMessage) {
	ctx := r.Context()

	var addKeyMsg protocol.AddKeyMessage
	if err := json.Unmarshal(msg.Message, &addKeyMsg); err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid AddKey message format")
		return
	}

	// --- Validation ---
	// Per the spec, the first key for an actor must be self-signed. Subsequent
	// keys must be signed by an existing, valid key for that actor.
	existingKeys, err := s.repo.ListKeysForActor(ctx, addKeyMsg.Actor)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to check for existing keys")
		return
	}

	if len(existingKeys) == 0 {
		// This is the first key, so it must be self-signed.
		pubKey, err := crypto.DecodePublicKey(addKeyMsg.PublicKey)
		if err != nil {
			s.respondWithError(w, http.StatusBadRequest, "Invalid public key format for self-signing: "+err.Error())
			return
		}
		if err := crypto.VerifyMessageSignature(msg, pubKey); err != nil {
			s.respondWithError(w, http.StatusUnauthorized, "Invalid self-signature on first AddKey message")
			return
		}
	} else {
		// An existing key must sign this new key.
		var validSignature bool
		for _, key := range existingKeys {
			pubKey, err := crypto.DecodePublicKey(key.PublicKey)
			if err != nil {
				s.logger.Printf("Skipping invalid public key in database: %s", key.KeyID)
				continue
			}
			if err := crypto.VerifyMessageSignature(msg, pubKey); err == nil {
				validSignature = true
				break
			}
		}
		if !validSignature {
			s.respondWithError(w, http.StatusUnauthorized, "Invalid signature: AddKey must be signed by an existing key")
			return
		}
	}

	// --- Processing ---
	// Create the canonical message form for SigSum submission.
	signedMsg := protocol.SignedMessage{
		PKDContext:       msg.PKDContext,
		Action:           msg.Action,
		Message:          msg.Message,
		RecentMerkleRoot: msg.RecentMerkleRoot,
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to marshal message for SigSum")
		return
	}

	// Submit to SigSum to be included in the transparency log.
	merkleRoot, err := s.sigsum.SubmitMessage(ctx, signedMsgBytes)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to submit message to SigSum")
		return
	}

	// Decode symmetric keys for crypto-shredding.
	decodedSymKeys := make(map[string][]byte)
	for attr, keyStr := range msg.SymmetricKeys {
		keyBytes, err := base64.RawURLEncoding.DecodeString(keyStr)
		if err != nil {
			s.respondWithError(w, http.StatusBadRequest, "Invalid base64 for symmetric key: "+attr)
			return
		}
		decodedSymKeys[attr] = keyBytes
	}

	// Process the action in the domain service, which handles database operations.
	newKey, err := s.service.ProcessAddKey(ctx, &addKeyMsg, merkleRoot, decodedSymKeys)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to process AddKey in database: "+err.Error())
		return
	}

	s.respondWithJSON(w, http.StatusOK, map[string]string{
		"key_id":      newKey.KeyID,
		"merkle_root": newKey.MerkleRoot,
	})
}

// processRevokeKeyAction handles the "RevokeKey" protocol message.
// It ensures the actor has other keys remaining and that the signature is from
// a different, valid key.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#revokekey-validation-steps
func (s *Server) processRevokeKeyAction(w http.ResponseWriter, r *http.Request, msg *protocol.ProtocolMessage) {
	ctx := r.Context()

	var revokeMsg protocol.RevokeKeyMessage
	if err := json.Unmarshal(msg.Message, &revokeMsg); err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid RevokeKey message format")
		return
	}

	// Fetch existing keys to perform validation.
	existingKeys, err := s.repo.ListKeysForActor(ctx, revokeMsg.Actor)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to fetch existing keys")
		return
	}

	// Spec rule: Cannot revoke the last key with RevokeKey. Use BurnDown instead.
	if len(existingKeys) < 2 {
		s.respondWithError(w, http.StatusBadRequest, "Cannot use RevokeKey on the last remaining key")
		return
	}

	keyToRevoke, err := crypto.DecodePublicKey(revokeMsg.PublicKey)
	if err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid public key format in revocation message")
		return
	}

	// Spec rule: The revocation must be signed by a *different* valid key
	// belonging to the same actor.
	var validSignature bool
	for _, key := range existingKeys {
		signingPubKey, err := crypto.DecodePublicKey(key.PublicKey)
		if err != nil {
			continue
		}
		// The key being revoked cannot be the one signing the revocation.
		if signingPubKey.Equal(keyToRevoke) {
			continue
		}
		if err := crypto.VerifyMessageSignature(msg, signingPubKey); err == nil {
			validSignature = true
			break
		}
	}
	if !validSignature {
		s.respondWithError(w, http.StatusUnauthorized, "Invalid signature: RevokeKey must be signed by another valid key for the actor")
		return
	}

	// Submit to SigSum.
	signedMsg := protocol.SignedMessage{
		PKDContext:       msg.PKDContext,
		Action:           msg.Action,
		Message:          msg.Message,
		RecentMerkleRoot: msg.RecentMerkleRoot,
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to marshal message for SigSum")
		return
	}
	merkleRoot, err := s.sigsum.SubmitMessage(ctx, signedMsgBytes)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to submit message to SigSum")
		return
	}

	// Decode symmetric keys for crypto-shredding.
	decodedSymKeys := make(map[string][]byte)
	for attr, keyStr := range msg.SymmetricKeys {
		keyBytes, err := base64.RawURLEncoding.DecodeString(keyStr)
		if err != nil {
			s.respondWithError(w, http.StatusBadRequest, "Invalid base64 for symmetric key: "+attr)
			return
		}
		decodedSymKeys[attr] = keyBytes
	}

	// Process the revocation in the domain service.
	if err := s.service.ProcessRevokeKey(ctx, &revokeMsg, merkleRoot, decodedSymKeys); err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to process RevokeKey in database: "+err.Error())
		return
	}

	s.respondWithJSON(w, http.StatusOK, map[string]string{"status": "RevokeKey processed successfully"})
}

// processMoveIdentityAction handles the "MoveIdentity" protocol message.
// This allows a user to migrate their identity to a new Actor ID, for instance,
// when moving between Fediverse instances.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#moveidentity-validation-steps
func (s *Server) processMoveIdentityAction(w http.ResponseWriter, r *http.Request, msg *protocol.ProtocolMessage) {
	ctx := r.Context()

	var moveMsg protocol.MoveIdentityMessage
	if err := json.Unmarshal(msg.Message, &moveMsg); err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid MoveIdentity message format")
		return
	}

	// The message must be signed by a key from the old actor ID.
	existingKeys, err := s.repo.ListKeysForActor(ctx, moveMsg.OldActor)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to fetch existing keys for old actor")
		return
	}
	if len(existingKeys) == 0 {
		s.respondWithError(w, http.StatusBadRequest, "Old actor has no keys to sign with")
		return
	}

	var validSignature bool
	for _, key := range existingKeys {
		pubKey, err := crypto.DecodePublicKey(key.PublicKey)
		if err != nil {
			continue
		}
		if err := crypto.VerifyMessageSignature(msg, pubKey); err == nil {
			validSignature = true
			break
		}
	}
	if !validSignature {
		s.respondWithError(w, http.StatusUnauthorized, "Invalid signature: MoveIdentity must be signed by a key from the old actor")
		return
	}

	// Submit to SigSum.
	signedMsg := protocol.SignedMessage{
		PKDContext:       msg.PKDContext,
		Action:           msg.Action,
		Message:          msg.Message,
		RecentMerkleRoot: msg.RecentMerkleRoot,
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to marshal message for SigSum")
		return
	}
	merkleRoot, err := s.sigsum.SubmitMessage(ctx, signedMsgBytes)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to submit message to SigSum")
		return
	}

	// Process the move in the domain service.
	if err := s.service.ProcessMoveIdentity(ctx, &moveMsg, merkleRoot); err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to process MoveIdentity in database: "+err.Error())
		return
	}

	s.respondWithJSON(w, http.StatusOK, map[string]string{"status": "MoveIdentity processed successfully"})
}

// processBurnDownAction handles the "BurnDown" protocol message, a break-glass
// mechanism for account recovery. It requires a valid signature from the instance
// operator and a valid TOTP if configured.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#burndown-validation-steps
func (s *Server) processBurnDownAction(w http.ResponseWriter, r *http.Request, msg *protocol.ProtocolMessage) {
	ctx := r.Context()

	var burnMsg protocol.BurnDownMessage
	if err := json.Unmarshal(msg.Message, &burnMsg); err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid BurnDown message format")
		return
	}

	// The message must be signed by the operator, not the user being burned.
	operatorKeys, err := s.repo.ListKeysForActor(ctx, burnMsg.Operator)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to fetch existing keys for operator")
		return
	}
	if len(operatorKeys) == 0 {
		s.respondWithError(w, http.StatusBadRequest, "Operator has no keys to sign with")
		return
	}

	var validSignature bool
	for _, key := range operatorKeys {
		pubKey, err := crypto.DecodePublicKey(key.PublicKey)
		if err != nil {
			continue
		}
		if err := crypto.VerifyMessageSignature(msg, pubKey); err == nil {
			validSignature = true
			break
		}
	}
	if !validSignature {
		s.respondWithError(w, http.StatusUnauthorized, "Invalid signature: BurnDown must be signed by a key from the operator")
		return
	}

	// TOTP validation is required if the instance has enrolled a secret.
	encryptedSecret, err := s.repo.GetTOTPSecret(ctx, burnMsg.Operator)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve TOTP secret")
		return
	}

	// Only perform TOTP validation if a secret is configured for the operator.
	if encryptedSecret != nil {
		if msg.OTP == "" {
			s.respondWithError(w, http.StatusBadRequest, "Missing OTP for BurnDown action")
			return
		}

		// Decrypt the TOTP secret and validate the provided OTP.
		privateKey, ok := s.hpkePrivateKey.(kem.PrivateKey)
		if !ok {
			s.logger.Printf("Server's HPKE private key is not of the expected type")
			s.respondWithError(w, http.StatusInternalServerError, "Internal server error processing key")
			return
		}
		secret, err := crypto.DecryptWithHPKE(privateKey, encryptedSecret)
		if err != nil {
			s.logger.Printf("Failed to decrypt TOTP secret: %v", err)
			s.respondWithError(w, http.StatusInternalServerError, "Could not process TOTP secret")
			return
		}
		if !crypto.ValidateTOTP(string(secret), msg.OTP) {
			s.respondWithError(w, http.StatusUnauthorized, "Invalid OTP")
			return
		}
	}
	// If encryptedSecret is nil, we proceed without OTP validation, as per spec.

	// Submit to SigSum.
	signedMsg := protocol.SignedMessage{
		PKDContext:       msg.PKDContext,
		Action:           msg.Action,
		Message:          msg.Message,
		RecentMerkleRoot: msg.RecentMerkleRoot,
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to marshal message for SigSum")
		return
	}
	merkleRoot, err := s.sigsum.SubmitMessage(ctx, signedMsgBytes)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to submit message to SigSum")
		return
	}

	// Process the burn down in the domain service.
	if err := s.service.ProcessBurnDown(ctx, burnMsg.Actor, merkleRoot); err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to process BurnDown in database: "+err.Error())
		return
	}

	s.respondWithJSON(w, http.StatusOK, map[string]string{"status": "BurnDown processed successfully"})
}

// processFireproofAction handles the "Fireproof" message, which allows a user
// to disable the BurnDown capability for their account.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#fireproof-validation-steps
func (s *Server) processFireproofAction(w http.ResponseWriter, r *http.Request, msg *protocol.ProtocolMessage) {
	ctx := r.Context()

	var fireproofMsg protocol.FireproofMessage
	if err := json.Unmarshal(msg.Message, &fireproofMsg); err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid Fireproof message format")
		return
	}

	// The message must be signed by one of the actor's keys.
	existingKeys, err := s.repo.ListKeysForActor(ctx, fireproofMsg.Actor)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to fetch existing keys for actor")
		return
	}
	if len(existingKeys) == 0 {
		s.respondWithError(w, http.StatusBadRequest, "Actor has no keys to sign with")
		return
	}

	var validSignature bool
	for _, key := range existingKeys {
		pubKey, err := crypto.DecodePublicKey(key.PublicKey)
		if err != nil {
			continue
		}
		if err := crypto.VerifyMessageSignature(msg, pubKey); err == nil {
			validSignature = true
			break
		}
	}
	if !validSignature {
		s.respondWithError(w, http.StatusUnauthorized, "Invalid signature: Fireproof must be signed by a key from the actor")
		return
	}

	// Submit to SigSum.
	signedMsg := protocol.SignedMessage{
		PKDContext:       msg.PKDContext,
		Action:           msg.Action,
		Message:          msg.Message,
		RecentMerkleRoot: msg.RecentMerkleRoot,
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to marshal message for SigSum")
		return
	}
	if _, err := s.sigsum.SubmitMessage(ctx, signedMsgBytes); err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to submit message to SigSum")
		return
	}

	// Set the fireproof status in the database.
	if err := s.repo.SetFireproof(ctx, fireproofMsg.Actor, true); err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to set fireproof status: "+err.Error())
		return
	}

	s.respondWithJSON(w, http.StatusOK, map[string]string{"status": "Fireproof processed successfully"})
}

// processUndoFireproofAction handles the "UndoFireproof" message, re-enabling
// the BurnDown capability.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#undofireproof-validation-steps
func (s *Server) processUndoFireproofAction(w http.ResponseWriter, r *http.Request, msg *protocol.ProtocolMessage) {
	ctx := r.Context()

	var undoMsg protocol.UndoFireproofMessage
	if err := json.Unmarshal(msg.Message, &undoMsg); err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid UndoFireproof message format")
		return
	}

	// The message must be signed by one of the actor's keys.
	existingKeys, err := s.repo.ListKeysForActor(ctx, undoMsg.Actor)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to fetch existing keys for actor")
		return
	}
	if len(existingKeys) == 0 {
		s.respondWithError(w, http.StatusBadRequest, "Actor has no keys to sign with")
		return
	}

	var validSignature bool
	for _, key := range existingKeys {
		pubKey, err := crypto.DecodePublicKey(key.PublicKey)
		if err != nil {
			continue
		}
		if err := crypto.VerifyMessageSignature(msg, pubKey); err == nil {
			validSignature = true
			break
		}
	}
	if !validSignature {
		s.respondWithError(w, http.StatusUnauthorized, "Invalid signature: UndoFireproof must be signed by a key from the actor")
		return
	}

	// Submit to SigSum.
	signedMsg := protocol.SignedMessage{
		PKDContext:       msg.PKDContext,
		Action:           msg.Action,
		Message:          msg.Message,
		RecentMerkleRoot: msg.RecentMerkleRoot,
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to marshal message for SigSum")
		return
	}
	if _, err := s.sigsum.SubmitMessage(ctx, signedMsgBytes); err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to submit message to SigSum")
		return
	}

	// Unset the fireproof status in the database.
	if err := s.repo.SetFireproof(ctx, undoMsg.Actor, false); err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to set fireproof status: "+err.Error())
		return
	}

	s.respondWithJSON(w, http.StatusOK, map[string]string{"status": "UndoFireproof processed successfully"})
}

// processAddAuxDataAction handles the "AddAuxData" message, allowing clients
// to store arbitrary data associated with an actor, as defined by an extension.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addauxdata-validation-steps
func (s *Server) processAddAuxDataAction(w http.ResponseWriter, r *http.Request, msg *protocol.ProtocolMessage) {
	ctx := r.Context()

	var addAuxMsg protocol.AddAuxDataMessage
	if err := json.Unmarshal(msg.Message, &addAuxMsg); err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid AddAuxData message format")
		return
	}

	// The message must be signed by one of the actor's keys.
	existingKeys, err := s.repo.ListKeysForActor(ctx, addAuxMsg.Actor)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to fetch existing keys for actor")
		return
	}
	if len(existingKeys) == 0 {
		s.respondWithError(w, http.StatusBadRequest, "Actor has no keys to sign with")
		return
	}

	var validSignature bool
	for _, key := range existingKeys {
		pubKey, err := crypto.DecodePublicKey(key.PublicKey)
		if err != nil {
			continue
		}
		if err := crypto.VerifyMessageSignature(msg, pubKey); err == nil {
			validSignature = true
			break
		}
	}
	if !validSignature {
		s.respondWithError(w, http.StatusUnauthorized, "Invalid signature: AddAuxData must be signed by a key from the actor")
		return
	}

	// Submit to SigSum.
	signedMsg := protocol.SignedMessage{
		PKDContext:       msg.PKDContext,
		Action:           msg.Action,
		Message:          msg.Message,
		RecentMerkleRoot: msg.RecentMerkleRoot,
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to marshal message for SigSum")
		return
	}
	merkleRoot, err := s.sigsum.SubmitMessage(ctx, signedMsgBytes)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to submit message to SigSum")
		return
	}

	// Process the new auxiliary data in the domain service.
	newAux, err := s.service.ProcessAddAuxData(ctx, &addAuxMsg, merkleRoot)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to process AddAuxData in database: "+err.Error())
		return
	}

	s.respondWithJSON(w, http.StatusOK, map[string]string{"aux_id": newAux.AuxID})
}

// processRevokeAuxDataAction handles the "RevokeAuxData" message.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#revokeauxdata-validation-steps
func (s *Server) processRevokeAuxDataAction(w http.ResponseWriter, r *http.Request, msg *protocol.ProtocolMessage) {
	ctx := r.Context()

	var revokeAuxMsg protocol.RevokeAuxDataMessage
	if err := json.Unmarshal(msg.Message, &revokeAuxMsg); err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid RevokeAuxData message format")
		return
	}

	// The message must be signed by one of the actor's keys.
	existingKeys, err := s.repo.ListKeysForActor(ctx, revokeAuxMsg.Actor)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to fetch existing keys for actor")
		return
	}
	if len(existingKeys) == 0 {
		s.respondWithError(w, http.StatusBadRequest, "Actor has no keys to sign with")
		return
	}

	var validSignature bool
	for _, key := range existingKeys {
		pubKey, err := crypto.DecodePublicKey(key.PublicKey)
		if err != nil {
			continue
		}
		if err := crypto.VerifyMessageSignature(msg, pubKey); err == nil {
			validSignature = true
			break
		}
	}
	if !validSignature {
		s.respondWithError(w, http.StatusUnauthorized, "Invalid signature: RevokeAuxData must be signed by a key from the actor")
		return
	}

	// Submit to SigSum.
	signedMsg := protocol.SignedMessage{
		PKDContext:       msg.PKDContext,
		Action:           msg.Action,
		Message:          msg.Message,
		RecentMerkleRoot: msg.RecentMerkleRoot,
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to marshal message for SigSum")
		return
	}
	merkleRoot, err := s.sigsum.SubmitMessage(ctx, signedMsgBytes)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to submit message to SigSum")
		return
	}

	// Process the revocation in the domain service.
	if err := s.service.ProcessRevokeAuxData(ctx, &revokeAuxMsg, merkleRoot); err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to process RevokeAuxData in database: "+err.Error())
		return
	}

	s.respondWithJSON(w, http.StatusOK, map[string]string{"status": "RevokeAuxData processed successfully"})
}

// processQueryAction handles the "Query" protocol message. It returns the
// current list of valid public keys for a given actor.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#query-message
func (s *Server) processQueryAction(w http.ResponseWriter, r *http.Request, msg *protocol.ProtocolMessage) {
	ctx := r.Context()

	var queryMsg protocol.QueryMessage
	if err := json.Unmarshal(msg.Message, &queryMsg); err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid Query message format")
		return
	}

	keys, err := s.repo.ListKeysForActor(ctx, queryMsg.Actor)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve actor keys")
		return
	}

	// The response should be a list of public key objects.
	s.respondWithJSON(w, http.StatusOK, keys)
}

// processCheckpointAction handles the "Checkpoint" message, part of the
// active gossip protocol for cross-validating PKD instances.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#checkpoint-validation-steps
func (s *Server) processCheckpointAction(w http.ResponseWriter, r *http.Request, msg *protocol.ProtocolMessage) {
	ctx := r.Context()

	var checkpointMsg protocol.CheckpointMessage
	if err := json.Unmarshal(msg.Message, &checkpointMsg); err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid Checkpoint message format")
		return
	}

	// The sender of the checkpoint must be a configured peer.
	signingKey, err := s.getDirectoryPublicKey(checkpointMsg.FromDirectory)
	if err != nil {
		// Differentiate between "not found" and other errors for the client.
		s.respondWithError(w, http.StatusBadRequest, "Unknown or invalid from-directory: "+err.Error())
		return
	}

	// Verify the signature using the peer's configured public key.
	if err := crypto.VerifyMessageSignature(msg, signingKey); err != nil {
		s.respondWithError(w, http.StatusUnauthorized, "Invalid signature from directory server")
		return
	}

	// Unlike other messages, checkpoints are not submitted to SigSum in the same
	// way, but are stored locally.
	rawMsgBytes, err := json.Marshal(msg)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to re-marshal raw message")
		return
	}
	msgHash := crypto.HashBytes(rawMsgBytes)

	if err := s.repo.StoreMessage(ctx, msgHash, rawMsgBytes, msg); err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to store checkpoint message: "+err.Error())
		return
	}

	s.respondWithJSON(w, http.StatusOK, map[string]string{"status": "Checkpoint processed successfully"})
}
