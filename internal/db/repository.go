package db

import (
	"context"

	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/jmoiron/sqlx"
)

// Repository defines the interface for non-transactional database operations.
type Repository interface {
	DB() *sqlx.DB
	BeginTx(ctx context.Context) (domain.TransactionalRepository, error)

	// Actor operations
	FindActorByActorID(ctx context.Context, actorID string) (*domain.Actor, error)
	IsFireproof(ctx context.Context, actorID string) (bool, error)
	SetFireproof(ctx context.Context, actorID string, isFireproof bool) error

	// Key operations
	ListKeysForActor(ctx context.Context, actorID string) ([]*domain.PublicKey, error)
	FindKeyByKeyID(ctx context.Context, keyID string) (*domain.PublicKey, error)

	// Auxiliary data operations
	ListAuxDataForActor(ctx context.Context, actorID string) ([]*domain.AuxiliaryData, error)
	FindAuxDataByAuxID(ctx context.Context, auxID string) (*domain.AuxiliaryData, error)

	// Symmetric key management
	FindSymmetricKeysByMessageHash(ctx context.Context, messageHash string) ([]*domain.SymmetricKey, error)

	// General message logging
	StoreMessage(ctx context.Context, hash string, rawMessage []byte, decryptedMessage *protocol.ProtocolMessage) error
	GetLatestMerkleRoot(ctx context.Context) (string, error)

	// TOTP Management
	StoreTOTPSecret(ctx context.Context, instance string, encryptedSecret []byte) error
	GetTOTPSecret(ctx context.Context, instance string) ([]byte, error)
	DeleteTOTPSecret(ctx context.Context, instance string) error

	// Health check
	Ping(ctx context.Context) error
	Close() error
}
