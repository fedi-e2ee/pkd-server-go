// Package tlog provides a mock client for the tlog.
package tlog

import (
	"context"

	"github.com/stretchr/testify/mock"
)

// MockClient is a mock implementation of the Client interface.
type MockClient struct {
	mock.Mock
}

// SubmitMessage mocks the SubmitMessage method.
func (m *MockClient) SubmitMessage(ctx context.Context, message []byte) (string, error) {
	args := m.Called(ctx, message)
	return args.String(0), args.Error(1)
}
