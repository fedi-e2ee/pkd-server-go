package tests

import (
	"context"

	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/stretchr/testify/mock"
)

// MockRepository is a mock implementation of the db.Repository interface.
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) BeginTx(ctx context.Context) (domain.TransactionalRepository, error) {
	args := m.Called(ctx)
	return args.Get(0).(domain.TransactionalRepository), args.Error(1)
}

func (m *MockRepository) FindActorByActorID(ctx context.Context, actorID string) (*domain.Actor, error) {
	args := m.Called(ctx, actorID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Actor), args.Error(1)
}

func (m *MockRepository) IsFireproof(ctx context.Context, actorID string) (bool, error) {
	args := m.Called(ctx, actorID)
	return args.Bool(0), args.Error(1)
}

func (m *MockRepository) SetFireproof(ctx context.Context, actorID string, isFireproof bool) error {
	args := m.Called(ctx, actorID, isFireproof)
	return args.Error(0)
}

func (m *MockRepository) ListKeysForActor(ctx context.Context, actorID string) ([]*domain.PublicKey, error) {
	args := m.Called(ctx, actorID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.PublicKey), args.Error(1)
}

func (m *MockRepository) FindKeyByKeyID(ctx context.Context, keyID string) (*domain.PublicKey, error) {
	args := m.Called(ctx, keyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.PublicKey), args.Error(1)
}

func (m *MockRepository) ListAuxDataForActor(ctx context.Context, actorID string) ([]*domain.AuxiliaryData, error) {
	args := m.Called(ctx, actorID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.AuxiliaryData), args.Error(1)
}

func (m *MockRepository) FindAuxDataByAuxID(ctx context.Context, auxID string) (*domain.AuxiliaryData, error) {
	args := m.Called(ctx, auxID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.AuxiliaryData), args.Error(1)
}

func (m *MockRepository) FindSymmetricKeysByMessageHash(ctx context.Context, messageHash string) ([]*domain.SymmetricKey, error) {
	args := m.Called(ctx, messageHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.SymmetricKey), args.Error(1)
}

func (m *MockRepository) StoreMessage(ctx context.Context, hash string, rawMessage []byte, decryptedMessage *protocol.ProtocolMessage) error {
	args := m.Called(ctx, hash, rawMessage, decryptedMessage)
	return args.Error(0)
}

func (m *MockRepository) GetLatestMerkleRoot(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

func (m *MockRepository) StoreTOTPSecret(ctx context.Context, instance string, encryptedSecret []byte) error {
	args := m.Called(ctx, instance, encryptedSecret)
	return args.Error(0)
}

func (m *MockRepository) GetTOTPSecret(ctx context.Context, instance string) ([]byte, error) {
	args := m.Called(ctx, instance)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockRepository) DeleteTOTPSecret(ctx context.Context, instance string) error {
	args := m.Called(ctx, instance)
	return args.Error(0)
}

func (m *MockRepository) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockRepository) Close() error {
	args := m.Called()
	return args.Error(0)
}
