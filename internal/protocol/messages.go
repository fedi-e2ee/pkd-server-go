package protocol

import "encoding/json"

// ProtocolMessage is the top-level structure for all incoming messages, as
// defined in the "Protocol Messages" section of the specification.
// It uses json.RawMessage for the 'message' field to allow for delayed
// parsing into the correct specific message struct based on the 'action'.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#protocol-messages
type ProtocolMessage struct {
	// PKDContext provides domain separation for the protocol version.
	PKDContext string `json:"!pkd-context"`
	// Action determines the type of operation (e.g., "AddKey", "RevokeKey").
	Action string `json:"action"`
	// KeyID is a hint to the server about which key to use for signature verification.
	// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#key-identifiers
	KeyID string `json:"key-id,omitempty"`
	// Message contains the action-specific payload.
	Message json.RawMessage `json:"message"`
	// RecentMerkleRoot is used for plaintext commitment and replay prevention.
	// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#recent-merkle-root-included-in-plaintext-commitments
	RecentMerkleRoot string `json:"recent-merkle-root"`
	// Signature is the digital signature over the canonical message form.
	Signature string `json:"signature"`
	// SymmetricKeys are disclosed to the server for decrypting message attributes, enabling crypto-shredding.
	// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#message-attribute-shreddability
	SymmetricKeys map[string]string `json:"symmetric-keys,omitempty"`
	// OTP is a one-time password, required for BurnDown messages if TOTP is enabled.
	// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#totp
	OTP string `json:"otp,omitempty"` // Specifically for BurnDown messages
}

// SignedMessage is used for creating the canonical JSON for signing. The
// signature covers this structure. The `message` field contains the raw JSON
// of the message payload to ensure the signature covers the exact original
// representation.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#protocol-signatures
type SignedMessage struct {
	PKDContext       string          `json:"!pkd-context"`
	Action           string          `json:"action"`
	Message          json.RawMessage `json:"message"`
	RecentMerkleRoot string          `json:"recent-merkle-root"`
}

// AddKeyMessage is the payload for an "AddKey" action, used to associate a
// new public key with an actor.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addkey
type AddKeyMessage struct {
	Actor     string `json:"actor"`
	Time      string `json:"time"`
	PublicKey string `json:"public-key"`
}

// RevokeKeyMessage is the payload for a "RevokeKey" action, used to mark an
// existing public key as untrusted.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#revokekey
type RevokeKeyMessage struct {
	Actor     string `json:"actor"`
	Time      string `json:"time"`
	PublicKey string `json:"public-key"`
}

// RevokeKeyThirdPartyMessage is a special message for third-party revocation,
// allowing anyone to revoke a key if they have a valid revocation token.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#revokekeythirdparty
type RevokeKeyThirdPartyMessage struct {
	Action          string `json:"action"`
	RevocationToken string `json:"revocation-token"`
}

// MoveIdentityMessage is the payload for a "MoveIdentity" action, used to
// migrate an actor's entire identity to a new Actor ID.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#moveidentity
type MoveIdentityMessage struct {
	OldActor string `json:"old-actor"`
	NewActor string `json:"new-actor"`
	Time     string `json:"time"`
}

// BurnDownMessage is the payload for a "BurnDown" action, which serves as a
// soft delete for all of an actor's data, enabling account recovery.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#burndown
type BurnDownMessage struct {
	Actor    string `json:"actor"`
	Operator string `json:"operator"`
	Time     string `json:"time"`
}

// FireproofMessage is the payload for a "Fireproof" action, allowing a user
// to opt out of the BurnDown account recovery mechanism.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#fireproof
type FireproofMessage struct {
	Actor string `json:"actor"`
	Time  string `json:"time"`
}

// UndoFireproofMessage is the payload for an "UndoFireproof" action, which
// re-enables the BurnDown mechanism for an actor.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#undofireproof
type UndoFireproofMessage struct {
	Actor string `json:"actor"`
	Time  string `json:"time"`
}

// AddAuxDataMessage is the payload for an "AddAuxData" action, used to
// associate arbitrary data with an actor, as defined by an extension.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addauxdata
type AddAuxDataMessage struct {
	Actor   string `json:"actor"`
	AuxType string `json:"aux-type"`
	AuxData string `json:"aux-data"`
	AuxID   string `json:"aux-id,omitempty"`
	Time    string `json:"time"`
}

// RevokeAuxDataMessage is the payload for a "RevokeAuxData" action, used to
// revoke a piece of auxiliary data.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#revokeauxdata
type RevokeAuxDataMessage struct {
	Actor   string `json:"actor"`
	AuxType string `json:"aux-type"`
	AuxData string `json:"aux-data,omitempty"`
	AuxID   string `json:"aux-id,omitempty"`
	Time    string `json:"time"`
}

// CheckpointMessage is the payload for a "Checkpoint" action, allowing one
// PKD instance to commit its Merkle root to another's log for cross-validation.
// QueryMessage is the payload for a "Query" action, which is used to request
// the public keys associated with an actor.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#query
type QueryMessage struct {
	Actor string `json:"actor"`
}

// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#checkpoint
type CheckpointMessage struct {
	Time            string `json:"time"`
	FromDirectory   string `json:"from-directory"`
	FromRoot        string `json:"from-root"`
	FromPublicKey   string `json:"from-public-key"`
	ToDirectory     string `json:"to-directory"`
	ToValidatedRoot string `json:"to-validated-root"`
}
