package mock

import (
	"context"

	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/stretchr/testify/mock"
)

// Service is a mock implementation of the domain.Service.
type Service struct {
	mock.Mock
}

// CryptoShred is a mock implementation of the CryptoShred method.
func (s *Service) CryptoShred(ctx context.Context, actorID string) error {
	args := s.Called(ctx, actorID)
	return args.Error(0)
}

// ProcessAddKey is a mock implementation of the ProcessAddKey method.
func (s *Service) ProcessAddKey(ctx context.Context, msg *protocol.AddKeyMessage, merkleRoot string, symKeys map[string][]byte) (*domain.PublicKey, error) {
	args := s.Called(ctx, msg, merkleRoot, symKeys)
	if key, ok := args.Get(0).(*domain.PublicKey); ok {
		return key, args.Error(1)
	}
	return nil, args.Error(1)
}

// ProcessRevokeKey is a mock implementation of the ProcessRevokeKey method.
func (s *Service) ProcessRevokeKey(ctx context.Context, msg *protocol.RevokeKeyMessage, merkleRoot string, symKeys map[string][]byte) error {
	args := s.Called(ctx, msg, merkleRoot, symKeys)
	return args.Error(0)
}

// ProcessMoveIdentity is a mock implementation of the ProcessMoveIdentity method.
func (s *Service) ProcessMoveIdentity(ctx context.Context, msg *protocol.MoveIdentityMessage, merkleRoot string) error {
	args := s.Called(ctx, msg, merkleRoot)
	return args.Error(0)
}

// ProcessBurnDown is a mock implementation of the ProcessBurnDown method.
func (s *Service) ProcessBurnDown(ctx context.Context, actorID string, merkleRoot string) error {
	args := s.Called(ctx, actorID, merkleRoot)
	return args.Error(0)
}

// ProcessAddAuxData is a mock implementation of the ProcessAddAuxData method.
func (s *Service) ProcessAddAuxData(ctx context.Context, msg *protocol.AddAuxDataMessage, merkleRoot string) (*domain.AuxiliaryData, error) {
	args := s.Called(ctx, msg, merkleRoot)
	if data, ok := args.Get(0).(*domain.AuxiliaryData); ok {
		return data, args.Error(1)
	}
	return nil, args.Error(1)
}

// ProcessRevokeAuxData is a mock implementation of the ProcessRevokeAuxData method.
func (s *Service) ProcessRevokeAuxData(ctx context.Context, msg *protocol.RevokeAuxDataMessage, merkleRoot string) error {
	args := s.Called(ctx, msg, merkleRoot)
	return args.Error(0)
}
