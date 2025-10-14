package mock

import (
	"context"

	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/stretchr/testify/mock"
)

// Repository is a mock implementation of the db.Repository interface.
type Repository struct {
	mock.Mock
}

// FindActorByActorID mocks the FindActorByActorID method.
func (m *Repository) FindActorByActorID(ctx context.Context, actorID string) (*domain.Actor, error) {
	args := m.Called(ctx, actorID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Actor), args.Error(1)
}

// BeginTx mocks the BeginTx method.
func (m *Repository) BeginTx(ctx context.Context) (domain.TransactionalRepository, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(domain.TransactionalRepository), args.Error(1)
}

// IsFireproof mocks the IsFireproof method.
func (m *Repository) IsFireproof(ctx context.Context, actorID string) (bool, error) {
	args := m.Called(ctx, actorID)
	return args.Bool(0), args.Error(1)
}

// FindSymmetricKeysByMessageHash mocks the FindSymmetricKeysByMessageHash method.
func (m *Repository) FindSymmetricKeysByMessageHash(ctx context.Context, messageHash string) ([]*domain.SymmetricKey, error) {
	args := m.Called(ctx, messageHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.SymmetricKey), args.Error(1)
}

// StoreTOTPSecret mocks the StoreTOTPSecret method.
func (m *Repository) StoreTOTPSecret(ctx context.Context, instance string, encryptedSecret []byte) error {
	args := m.Called(ctx, instance, encryptedSecret)
	return args.Error(0)
}

// DeleteTOTPSecret mocks the DeleteTOTPSecret method.
func (m *Repository) DeleteTOTPSecret(ctx context.Context, instance string) error {
	args := m.Called(ctx, instance)
	return args.Error(0)
}

// Ping mocks the Ping method.
func (m *Repository) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// Close mocks the Close method.
func (m *Repository) Close() error {
	args := m.Called()
	return args.Error(0)
}

// ListKeysForActor mocks the ListKeysForActor method.
func (m *Repository) ListKeysForActor(ctx context.Context, actorID string) ([]*domain.PublicKey, error) {
	args := m.Called(ctx, actorID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.PublicKey), args.Error(1)
}

// FindKeyByKeyID mocks the FindKeyByKeyID method.
func (m *Repository) FindKeyByKeyID(ctx context.Context, keyID string) (*domain.PublicKey, error) {
	args := m.Called(ctx, keyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.PublicKey), args.Error(1)
}

// ListAuxDataForActor mocks the ListAuxDataForActor method.
func (m *Repository) ListAuxDataForActor(ctx context.Context, actorID string) ([]*domain.AuxiliaryData, error) {
	args := m.Called(ctx, actorID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.AuxiliaryData), args.Error(1)
}

// FindAuxDataByAuxID mocks the FindAuxDataByAuxID method.
func (m *Repository) FindAuxDataByAuxID(ctx context.Context, auxID string) (*domain.AuxiliaryData, error) {
	args := m.Called(ctx, auxID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.AuxiliaryData), args.Error(1)
}

// GetLatestMerkleRoot mocks the GetLatestMerkleRoot method.
func (m *Repository) GetLatestMerkleRoot(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

// StoreMessage mocks the StoreMessage method.
func (m *Repository) StoreMessage(ctx context.Context, hash string, rawMsg []byte, msg *protocol.ProtocolMessage) error {
	args := m.Called(ctx, hash, rawMsg, msg)
	return args.Error(0)
}

// SetFireproof mocks the SetFireproof method.
func (m *Repository) SetFireproof(ctx context.Context, actorID string, fireproof bool) error {
	args := m.Called(ctx, actorID, fireproof)
	return args.Error(0)
}

// GetTOTPSecret mocks the GetTOTPSecret method.
func (m *Repository) GetTOTPSecret(ctx context.Context, actorID string) ([]byte, error) {
	args := m.Called(ctx, actorID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// CreateActor mocks the CreateActor method.
func (m *Repository) CreateActor(ctx context.Context, actorID string) (*domain.Actor, error) {
	args := m.Called(ctx, actorID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Actor), args.Error(1)
}
