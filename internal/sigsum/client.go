// Package sigsum is the SigSum implementation.
package sigsum

import (
	"context"
)

// Client defines the interface for interacting with a SigSum transparency log.
type Client interface {
	// SubmitMessage submits a message to the SigSum log.
	// The message is the raw byte slice of the JSON data to be stored and signed.
	// It returns the new Merkle root from SigSum upon successful inclusion.
	SubmitMessage(ctx context.Context, message []byte) (string, error)
}
