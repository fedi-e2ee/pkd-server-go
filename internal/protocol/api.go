package protocol

import "encoding/json"

// This file defines the Go structs that correspond to the JSON responses for
// the Public Key Directory's REST API, as detailed in the specification.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#json-rest-api

// --- Actor API Responses ---

// ActorInfoResponse is the response for `GET /api/actor/:actor_id`.
// It provides a summary of an actor's data in the PKD.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#get-apiactoractor_id
type ActorInfoResponse struct {
	PKDContext string `json:"!pkd-context"`
	ActorID    string `json:"actor-id"`
	CountAux   int    `json:"count-aux"`
	CountKeys  int    `json:"count-keys"`
}

// ActorKeysResponse is the response for `GET /api/actor/:actor_id/keys`.
// It lists all currently-trusted public keys for a given actor.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#get-apiactoractor_idkeys
type ActorKeysResponse struct {
	PKDContext string      `json:"!pkd-context"`
	ActorID    string      `json:"actor-id"`
	PublicKeys []PublicKey `json:"public-keys"`
}

// KeyInfoResponse is the response for `GET /api/actor/:actor_id/key/:key_id`.
// It provides detailed information about a specific public key.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#get-apiactoractor_idkeykey_id
type KeyInfoResponse struct {
	PKDContext     string   `json:"!pkd-context"`
	ActorID        string   `json:"actor-id"`
	Created        string   `json:"created"`
	InclusionProof []string `json:"inclusion-proof"`
	KeyID          string   `json:"key-id"`
	MerkleRoot     string   `json:"merkle-root"`
	PublicKey      string   `json:"public-key"`
	Revoked        *string  `json:"revoked"`     // Pointer to allow for null
	RevokeRoot     *string  `json:"revoke-root"` // Pointer to allow for null
}

// ActorAuxiliaryResponse is the response for `GET /api/actor/:actor_id/auxiliary`.
// It lists all currently-trusted auxiliary data for a given actor.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#get-apiactoractor_idauxiliary
type ActorAuxiliaryResponse struct {
	PKDContext string          `json:"!pkd-context"`
	ActorID    string          `json:"actor-id"`
	Auxiliary  []AuxiliaryInfo `json:"auxiliary"`
}

// AuxiliaryDataInfoResponse is the response for `GET /api/actor/:actor_id/auxiliary/:aux_data_id`.
// It provides detailed information about a specific piece of auxiliary data.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#get-apiactoractor_idauxiliaryaux_data_id
type AuxiliaryDataInfoResponse struct {
	PKDContext     string   `json:"!pkd-context"`
	ActorID        string   `json:"actor-id"`
	AuxData        string   `json:"aux-data"`
	AuxID          string   `json:"aux-id"`
	AuxType        string   `json:"aux-type"`
	Created        string   `json:"created"`
	InclusionProof []string `json:"inclusion-proof"`
	MerkleRoot     string   `json:"merkle-root"`
	Revoked        *string  `json:"revoked"`     // Pointer to allow for null
	RevokeRoot     *string  `json:"revoke-root"` // Pointer to allow for null
}

// --- History API Responses ---

// HistoryResponse is the response for `GET /api/history`.
// It returns the latest Merkle root of the directory's history.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#get-apihistory
type HistoryResponse struct {
	PKDContext  string `json:"!pkd-context"`
	CurrentTime string `json:"current-time"`
	Created     string `json:"created"`
	MerkleRoot  string `json:"merkle-root"`
}

// HistorySinceResponse is the response for `GET /api/history/since/:last_hash`.
// It lists a paginated set of history records since a given hash.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#get-apihistorysincelasthash
type HistorySinceResponse struct {
	PKDContext  string          `json:"!pkd-context"`
	CurrentTime string          `json:"current-time"`
	Records     []HistoryRecord `json:"records"`
}

// HistoryViewResponse is the response for `GET /api/history/view/:hash`.
// It returns detailed information about a specific historical record.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#get-apihistoryviewhash
type HistoryViewResponse struct {
	PKDContext       string                 `json:"!pkd-context"`
	Created          string                 `json:"created"`
	EncryptedMessage string                 `json:"encrypted-message"`
	InclusionProof   []string               `json:"inclusion-proof"`
	Message          *json.RawMessage       `json:"message"` // Pointer to allow for null
	MerkleRoot       string                 `json:"merkle-root"`
	RewrappedKeys    map[string]interface{} `json:"rewrapped-keys,omitempty"`
}

// --- Server Info API Responses ---

// ExtensionsResponse is the response for `GET /api/extensions`.
// It lists the auxiliary data extensions supported by the server.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#get-apiextensions
type ExtensionsResponse struct {
	PKDContext string      `json:"!pkd-context"`
	Time       string      `json:"time"`
	Extensions []Extension `json:"extensions"`
}

// ReplicasResponse is the response for `GET /api/replicas`.
// It lists other PKD instances that are replicated on this server.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#get-apireplicas
type ReplicasResponse struct {
	PKDContext string    `json:"!pkd-context"`
	Time       string    `json:"time"`
	Replicas   []Replica `json:"replicas"`
}

// ServerPublicKeyResponse is the response for `GET /api/server-public-key`.
// It provides the server's public key for HPKE encryption of protocol messages.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#get-apiserver-public-key
type ServerPublicKeyResponse struct {
	PKDContext      string `json:"!pkd-context"`
	CurrentTime     string `json:"current-time"`
	HPKECiphersuite string `json:"hpke-ciphersuite"`
	HPKEPublicKey   string `json:"hpke-public-key"`
}

// --- Action API Responses ---

// RevokeResponse is the response for `POST /api/revoke`.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#post-apirevoke
type RevokeResponse struct {
	PKDContext string `json:"!pkd-context"`
	Time       string `json:"time"`
}

// --- TOTP API Types ---

// TOTPDisenrollRequest is the payload for a `POST /api/totp/disenroll` request.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#post-apitotpdisenroll
type TOTPDisenrollRequest struct {
	ActorID string `json:"actor-id"`
	KeyID   string `json:"key-id"`
	OTP     string `json:"otp"`
}

// TOTPEnrollRequest is the payload for a `POST /api/totp/enroll` request.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#post-apitotpenroll
type TOTPEnrollRequest struct {
	ActorID      string `json:"actor-id"`
	KeyID        string `json:"key-id"`
	OTPCurrent   string `json:"otp-current"`
	OTPPrevious  string `json:"otp-previous"`
	TOTPSecret   string `json:"totp-secret"`
}

// TOTPRotateRequest is the payload for a `POST /api/totp/rotate` request.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#post-apitotprotate
type TOTPRotateRequest struct {
	ActorID        string `json:"actor-id"`
	KeyID          string `json:"key-id"`
	NewOTPCurrent  string `json:"new-otp-current"`
	NewOTPPrevious string `json:"new-otp-previous"`
	NewTOTPSecret  string `json:"new-totp-secret"`
	OldOTP         string `json:"old-otp"`
}

// TOTPGenericResponse is a generic success response for TOTP operations.
type TOTPGenericResponse struct {
	PKDContext string `json:"!pkd-context"`
	Success    bool   `json:"success"`
	Time       string `json:"time"`
}

// --- Helper Structs ---

// PublicKey represents a public key object in an API response.
type PublicKey struct {
	Created        string   `json:"created"`
	KeyID          string   `json:"key-id"`
	InclusionProof []string `json:"inclusion-proof"`
	MerkleRoot     string   `json:"merkle-root"`
	PublicKey      string   `json:"public-key"`
}

// AuxiliaryInfo represents an auxiliary data object in an API response.
type AuxiliaryInfo struct {
	AuxID   string `json:"aux-id"`
	AuxType string `json:"aux-type"`
	Created string `json:"created"`
}

// HistoryRecord represents a single record in the history.
type HistoryRecord struct {
	Created          string                 `json:"created"`
	EncryptedMessage string                 `json:"encrypted-message"`
	Message          *json.RawMessage       `json:"message"` // Pointer to allow for null
	MerkleRoot       string                 `json:"merkle-root"`
	RewrappedKeys    map[string]interface{} `json:"rewrapped-keys,omitempty"`
}

// Extension represents a supported auxiliary data extension.
type Extension struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Ref     string `json:"ref"`
}

// Replica represents a replicated PKD instance.
type Replica struct {
	ID  string `json:"id"`
	Ref string `json:"ref"`
}
