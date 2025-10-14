package sigsum

import (
	"context"

	"github.com/stretchr/testify/mock"
)

// MockClient is a mock implementation of the SigSum Client interface.
type MockClient struct {
	mock.Mock
}

// SubmitMessage is a mock implementation of the SubmitMessage method.
func (c *MockClient) SubmitMessage(ctx context.Context, message []byte) (string, error) {
	args := c.Called(ctx, message)
	return args.String(0), args.Error(1)
}
