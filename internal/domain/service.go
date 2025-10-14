package domain

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/fedi-e2ee/pkd-server-go/internal/auxvalidator"
	"github.com/fedi-e2ee/pkd-server-go/internal/crypto"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
)

// Repository defines the interface for database operations that can be part of a transaction.
type Repository interface {
	// Actor operations
	GetOrCreateActor(ctx context.Context, actorID string) (*Actor, error)
	FindActorByActorID(ctx context.Context, actorID string) (*Actor, error)
	ActorExists(ctx context.Context, actorID string) (bool, error)
	UpdateActorID(ctx context.Context, oldActorID, newActorID string) (int64, error)

	// Key operations
	InsertPublicKey(ctx context.Context, key *PublicKey) (*PublicKey, error)
	FindKeyToRevoke(ctx context.Context, actorID, publicKey string) (*PublicKey, error)
	RevokeKey(ctx context.Context, keyID int64, revokeRoot string) error
	GetMessageHashesForActor(ctx context.Context, actorID int64) ([]string, error)
	RevokeAllKeysForActor(ctx context.Context, actorID int64, merkleRoot string) error

	// Aux data operations
	InsertAuxData(ctx context.Context, aux *AuxiliaryData) (*AuxiliaryData, error)
	RevokeAuxData(ctx context.Context, actorID, auxID, revokeRoot string) (int64, error)

	// Symmetric key operations
	StoreSymmetricKeys(ctx context.Context, messageHash string, keys map[string][]byte) error
	DeleteSymmetricKeysByHashes(ctx context.Context, hashes []string) error
}

// TransactionalRepository extends the Repository with transaction control methods.
type TransactionalRepository interface {
	Repository
	Commit() error
	Rollback() error
}

// Transactioner defines the interface for a factory that can start a transaction.
type Transactioner interface {
	BeginTx(ctx context.Context) (TransactionalRepository, error)
}

// Service defines the interface for the PKD service.
type Service interface {
	CryptoShred(ctx context.Context, actorID string) error
	ProcessAddKey(ctx context.Context, msg *protocol.AddKeyMessage, merkleRoot string, symKeys map[string][]byte) (*PublicKey, error)
	ProcessRevokeKey(ctx context.Context, msg *protocol.RevokeKeyMessage, merkleRoot string, symKeys map[string][]byte) error
	ProcessMoveIdentity(ctx context.Context, msg *protocol.MoveIdentityMessage, merkleRoot string) error
	ProcessBurnDown(ctx context.Context, actorID string, merkleRoot string) error
	ProcessAddAuxData(ctx context.Context, msg *protocol.AddAuxDataMessage, merkleRoot string) (*AuxiliaryData, error)
	ProcessRevokeAuxData(ctx context.Context, msg *protocol.RevokeAuxDataMessage, merkleRoot string) error
}

// PKDService encapsulates the business logic of the PKD server.
type PKDService struct {
	db          Transactioner
	auxRegistry map[string]auxvalidator.AuxDataValidator
}

// NewPKDService creates a new PKDService.
func NewPKDService(db Transactioner, auxValidators []auxvalidator.AuxDataValidator) *PKDService {
	registry := make(map[string]auxvalidator.AuxDataValidator)
	for _, validator := range auxValidators {
		registry[validator.Type()] = validator
	}
	return &PKDService{
		db:          db,
		auxRegistry: registry,
	}
}

// ProcessAddKey handles the business logic for adding a new public key.
func (s *PKDService) ProcessAddKey(ctx context.Context, msg *protocol.AddKeyMessage, merkleRoot string, symKeys map[string][]byte) (*PublicKey, error) {
	tx, err := s.db.BeginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			log.Printf("Error rolling back transaction: %v", err)
		}
	}()

	actor, err := tx.GetOrCreateActor(ctx, msg.Actor)
	if err != nil {
		return nil, fmt.Errorf("failed to get or create actor: %w", err)
	}

	keyID, err := crypto.GenerateKeyID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}

	newKey := &PublicKey{
		ActorID:    actor.ID,
		KeyID:      keyID,
		PublicKey:  msg.PublicKey,
		MerkleRoot: merkleRoot,
	}

	insertedKey, err := tx.InsertPublicKey(ctx, newKey)
	if err != nil {
		return nil, fmt.Errorf("failed to insert public key: %w", err)
	}

	if len(symKeys) > 0 {
		if err := tx.StoreSymmetricKeys(ctx, merkleRoot, symKeys); err != nil {
			return nil, fmt.Errorf("failed to store symmetric keys: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return insertedKey, nil
}

// ProcessRevokeKey handles the business logic for revoking a public key.
func (s *PKDService) ProcessRevokeKey(ctx context.Context, msg *protocol.RevokeKeyMessage, merkleRoot string, symKeys map[string][]byte) error {
	tx, err := s.db.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			log.Printf("Error rolling back transaction: %v", err)
		}
	}()

	keyToRevoke, err := tx.FindKeyToRevoke(ctx, msg.Actor, msg.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to find key to revoke: %w", err)
	}
	if keyToRevoke == nil {
		return fmt.Errorf("key to revoke not found or already revoked: %s", msg.PublicKey)
	}

	if err := tx.RevokeKey(ctx, keyToRevoke.ID, merkleRoot); err != nil {
		return fmt.Errorf("failed to revoke key: %w", err)
	}

	if len(symKeys) > 0 {
		if err := tx.StoreSymmetricKeys(ctx, merkleRoot, symKeys); err != nil {
			return fmt.Errorf("failed to store symmetric keys for revocation: %w", err)
		}
	}

	return tx.Commit()
}

// CryptoShred performs a "burn down" operation initiated by an administrator.
func (s *PKDService) CryptoShred(ctx context.Context, actorID string) error {
	// For now, we can just call ProcessBurnDown. We can create a unique merkle root for admin actions if needed.
	// This could be a hash of the actorID and a timestamp, for example.
	merkleRoot := fmt.Sprintf("admin-shred-%s-%d", actorID, time.Now().UnixNano())
	return s.ProcessBurnDown(ctx, actorID, merkleRoot)
}

// ProcessMoveIdentity handles the business logic for changing an actor's ID.
func (s *PKDService) ProcessMoveIdentity(ctx context.Context, msg *protocol.MoveIdentityMessage, merkleRoot string) error {
	tx, err := s.db.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			log.Printf("Error rolling back transaction: %v", err)
		}
	}()

	exists, err := tx.ActorExists(ctx, msg.NewActor)
	if err != nil {
		return fmt.Errorf("failed to check for existing new actor ID: %w", err)
	}
	if exists {
		return fmt.Errorf("cannot move identity, new actor ID already exists: %s", msg.NewActor)
	}

	rowsAffected, err := tx.UpdateActorID(ctx, msg.OldActor, msg.NewActor)
	if err != nil {
		return fmt.Errorf("failed to update actor ID: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("actor to move not found: %s", msg.OldActor)
	}

	return tx.Commit()
}

// ProcessBurnDown handles the business logic for revoking all keys and crypto-shredding data for an actor.
func (s *PKDService) ProcessBurnDown(ctx context.Context, actorID string, merkleRoot string) error {
	tx, err := s.db.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			log.Printf("Error rolling back transaction: %v", err)
		}
	}()

	actor, err := tx.FindActorByActorID(ctx, actorID)
	if err != nil {
		return fmt.Errorf("failed to find actor for burn down: %w", err)
	}
	if actor == nil {
		return ErrActorNotFound
	}

	messageHashes, err := tx.GetMessageHashesForActor(ctx, actor.ID)
	if err != nil {
		return fmt.Errorf("failed to gather message hashes: %w", err)
	}

	if len(messageHashes) > 0 {
		if err := tx.DeleteSymmetricKeysByHashes(ctx, messageHashes); err != nil {
			return fmt.Errorf("failed to delete symmetric keys: %w", err)
		}
	}

	if err := tx.RevokeAllKeysForActor(ctx, actor.ID, merkleRoot); err != nil {
		return fmt.Errorf("failed to revoke all keys for actor: %w", err)
	}

	return tx.Commit()
}

// ProcessAddAuxData handles the business logic for adding auxiliary data.
func (s *PKDService) ProcessAddAuxData(ctx context.Context, msg *protocol.AddAuxDataMessage, merkleRoot string) (*AuxiliaryData, error) {
	if validator, ok := s.auxRegistry[msg.AuxType]; ok {
		if err := validator.Validate(msg.AuxData); err != nil {
			return nil, fmt.Errorf("auxiliary data validation failed: %w", err)
		}
	}

	tx, err := s.db.BeginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			log.Printf("Error rolling back transaction: %v", err)
		}
	}()

	actor, err := tx.GetOrCreateActor(ctx, msg.Actor)
	if err != nil {
		return nil, err
	}

	auxID, err := crypto.GenerateKeyID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate aux ID: %w", err)
	}

	newAux := &AuxiliaryData{
		ActorID:    actor.ID,
		AuxID:      auxID,
		AuxType:    msg.AuxType,
		AuxData:    msg.AuxData,
		MerkleRoot: merkleRoot,
		CreatedAt:  time.Now(),
	}

	insertedAux, err := tx.InsertAuxData(ctx, newAux)
	if err != nil {
		return nil, fmt.Errorf("failed to insert auxiliary data: %w", err)
	}

	return insertedAux, tx.Commit()
}

// ProcessRevokeAuxData handles the business logic for revoking auxiliary data.
func (s *PKDService) ProcessRevokeAuxData(ctx context.Context, msg *protocol.RevokeAuxDataMessage, merkleRoot string) error {
	tx, err := s.db.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			log.Printf("Error rolling back transaction: %v", err)
		}
	}()

	rowsAffected, err := tx.RevokeAuxData(ctx, msg.Actor, msg.AuxID, merkleRoot)
	if err != nil {
		return fmt.Errorf("failed to revoke auxiliary data: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("auxiliary data not found or already revoked: %s", msg.AuxID)
	}

	return tx.Commit()
}
