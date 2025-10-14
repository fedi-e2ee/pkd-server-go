package mock

import (
	"context"

	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/stretchr/testify/mock"
)

// Repository is a mock implementation of the domain.Repository interface.
type Repository struct {
	mock.Mock
}

// GetOrCreateActor is a mock implementation of the GetOrCreateActor method.
func (r *Repository) GetOrCreateActor(ctx context.Context, actorID string) (*domain.Actor, error) {
	args := r.Called(ctx, actorID)
	if actor, ok := args.Get(0).(*domain.Actor); ok {
		return actor, args.Error(1)
	}
	return nil, args.Error(1)
}

// FindActorByActorID is a mock implementation of the FindActorByActorID method.
func (r *Repository) FindActorByActorID(ctx context.Context, actorID string) (*domain.Actor, error) {
	args := r.Called(ctx, actorID)
	if actor, ok := args.Get(0).(*domain.Actor); ok {
		return actor, args.Error(1)
	}
	return nil, args.Error(1)
}

// ActorExists is a mock implementation of the ActorExists method.
func (r *Repository) ActorExists(ctx context.Context, actorID string) (bool, error) {
	args := r.Called(ctx, actorID)
	return args.Bool(0), args.Error(1)
}

// UpdateActorID is a mock implementation of the UpdateActorID method.
func (r *Repository) UpdateActorID(ctx context.Context, oldActorID, newActorID string) (int64, error) {
	args := r.Called(ctx, oldActorID, newActorID)
	return int64(args.Int(0)), args.Error(1)
}

// InsertPublicKey is a mock implementation of the InsertPublicKey method.
func (r *Repository) InsertPublicKey(ctx context.Context, key *domain.PublicKey) (*domain.PublicKey, error) {
	args := r.Called(ctx, key)
	if k, ok := args.Get(0).(*domain.PublicKey); ok {
		return k, args.Error(1)
	}
	return nil, args.Error(1)
}

// FindKeyToRevoke is a mock implementation of the FindKeyToRevoke method.
func (r *Repository) FindKeyToRevoke(ctx context.Context, actorID, publicKey string) (*domain.PublicKey, error) {
	args := r.Called(ctx, actorID, publicKey)
	if key, ok := args.Get(0).(*domain.PublicKey); ok {
		return key, args.Error(1)
	}
	return nil, args.Error(1)
}

// RevokeKey is a mock implementation of the RevokeKey method.
func (r *Repository) RevokeKey(ctx context.Context, keyID int64, revokeRoot string) error {
	args := r.Called(ctx, keyID, revokeRoot)
	return args.Error(0)
}

// GetMessageHashesForActor is a mock implementation of the GetMessageHashesForActor method.
func (r *Repository) GetMessageHashesForActor(ctx context.Context, actorID int64) ([]string, error) {
	args := r.Called(ctx, actorID)
	if hashes, ok := args.Get(0).([]string); ok {
		return hashes, args.Error(1)
	}
	return nil, args.Error(1)
}

// RevokeAllKeysForActor is a mock implementation of the RevokeAllKeysForActor method.
func (r *Repository) RevokeAllKeysForActor(ctx context.Context, actorID int64, merkleRoot string) error {
	args := r.Called(ctx, actorID, merkleRoot)
	return args.Error(0)
}

// InsertAuxData is a mock implementation of the InsertAuxData method.
func (r *Repository) InsertAuxData(ctx context.Context, aux *domain.AuxiliaryData) (*domain.AuxiliaryData, error) {
	args := r.Called(ctx, aux)
	if a, ok := args.Get(0).(*domain.AuxiliaryData); ok {
		return a, args.Error(1)
	}
	return nil, args.Error(1)
}

// RevokeAuxData is a mock implementation of the RevokeAuxData method.
func (r *Repository) RevokeAuxData(ctx context.Context, actorID, auxID, revokeRoot string) (int64, error) {
	args := r.Called(ctx, actorID, auxID, revokeRoot)
	return int64(args.Int(0)), args.Error(1)
}

// StoreSymmetricKeys is a mock implementation of the StoreSymmetricKeys method.
func (r *Repository) StoreSymmetricKeys(ctx context.Context, messageHash string, keys map[string][]byte) error {
	args := r.Called(ctx, messageHash, keys)
	return args.Error(0)
}

// DeleteSymmetricKeysByHashes is a mock implementation of the DeleteSymmetricKeysByHashes method.
func (r *Repository) DeleteSymmetricKeysByHashes(ctx context.Context, hashes []string) error {
	args := r.Called(ctx, hashes)
	return args.Error(0)
}

// ListKeysForActor is a mock implementation of the ListKeysForActor method.
func (r *Repository) ListKeysForActor(ctx context.Context, actorID string) ([]*domain.PublicKey, error) {
	args := r.Called(ctx, actorID)
	if keys, ok := args.Get(0).([]*domain.PublicKey); ok {
		return keys, args.Error(1)
	}
	return nil, args.Error(1)
}

// SetFireproof is a mock implementation of the SetFireproof method.
func (r *Repository) SetFireproof(ctx context.Context, actorID string, fireproof bool) error {
	args := r.Called(ctx, actorID, fireproof)
	return args.Error(0)
}

// GetTOTPSecret is a mock implementation of the GetTOTPSecret method.
func (r *Repository) GetTOTPSecret(ctx context.Context, actorID string) ([]byte, error) {
	args := r.Called(ctx, actorID)
	if secret, ok := args.Get(0).([]byte); ok {
		return secret, args.Error(1)
	}
	return nil, args.Error(1)
}

// StoreMessage is a mock implementation of the StoreMessage method.
func (r *Repository) StoreMessage(ctx context.Context, messageHash string, rawMessage []byte, msg *protocol.ProtocolMessage) error {
	args := r.Called(ctx, messageHash, rawMessage, msg)
	return args.Error(0)
}
