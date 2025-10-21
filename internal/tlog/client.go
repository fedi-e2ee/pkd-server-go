// Package tlog provides the client for the transparency log.
package tlog

import (
	"context"
)

// Client defines the interface for interacting with the transparency log.
type Client interface {
	// SubmitMessage submits a message to the transparency log.
	// The message is the raw byte slice of the JSON data to be stored and signed.
	// It returns the new Merkle root upon successful inclusion.
	SubmitMessage(ctx context.Context, message []byte) (string, error)
}
