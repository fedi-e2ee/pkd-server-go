package domain

import "time"

// Actor represents a user in the system.
type Actor struct {
	ID          int64     `db:"id"`
	ActorID     string    `db:"actor_id"`
	IsFireproof bool      `db:"is_fireproof"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

// PublicKey represents a public key associated with an actor.
type PublicKey struct {
	ID             int64      `db:"id" json:"id"`
	ActorID        int64      `db:"actor_id" json:"actor_id"`
	KeyID          string     `db:"key_id" json:"key_id"`
	PublicKey      string     `db:"public_key" json:"public_key"`
	CreatedAt      time.Time  `db:"created_at" json:"created_at"`
	MerkleRoot     string     `db:"merkle_root" json:"merkle_root"`
	RevokedAt      *time.Time `db:"revoked_at" json:"revoked_at"`
	RevokeRoot     *string    `db:"revoke_root" json:"revoke_root"`
	InclusionProof []string   `db:"-" json:"inclusion_proof,omitempty"`
}

// AuxiliaryData represents an auxiliary data record associated with an actor.
type AuxiliaryData struct {
	ID         int64      `db:"id"`
	ActorID    int64      `db:"actor_id"`
	AuxID      string     `db:"aux_id"`
	AuxType    string     `db:"aux_type"`
	AuxData    string     `db:"aux_data"`
	CreatedAt  time.Time  `db:"created_at"`
	MerkleRoot string     `db:"merkle_root"`
	RevokedAt  *time.Time `db:"revoked_at"` // Pointer to allow for null
	RevokeRoot *string    `db:"revoke_root"`  // Pointer to allow for null
}

// SymmetricKey represents a key used for attribute encryption, enabling crypto-shredding.
type SymmetricKey struct {
	ID          int64     `db:"id"`
	MessageHash string    `db:"message_hash"`
	Attribute   string    `db:"attribute"`
	Key         []byte    `db:"key"`
	CreatedAt   time.Time `db:"created_at"`
}

// MessageLog represents a raw protocol message stored for history and replay.
type MessageLog struct {
	ID               int64     `db:"id"`
	MessageHash      string    `db:"message_hash"`
	EncryptedMessage []byte    `db:"encrypted_message"`
	DecryptedMessage []byte    `db:"decrypted_message"` // Stored as JSON blob
	CreatedAt        time.Time `db:"created_at"`
}

// TOTPSecret represents a TOTP secret for a Fediverse instance.
type TOTPSecret struct {
	ID              int64     `db:"id"`
	Instance        string    `db:"instance"`
	EncryptedSecret []byte    `db:"encrypted_secret"`
	CreatedAt       time.Time `db:"created_at"`
	UpdatedAt       time.Time `db:"updated_at"`
}
