package domain

import "time"

// TlogEntry represents an entry in the transparency log.
type TlogEntry struct {
	ID            int       `db:"id"`
	MerkleRoot    []byte    `db:"merkle_root"`
	SignedMessage []byte    `db:"signed_message"`
	PublicKeyHash []byte    `db:"public_key_hash"`
	CreatedAt     time.Time `db:"created_at"`
}
