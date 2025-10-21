// Package tlog provides the database-backed tlog client.
package tlog

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"

	"github.com/fedi-e2ee/pkd-server-go/internal/db"
	"github.com/fedi-e2ee/pkd-server-go/internal/merkle"
)

// DBClient is a concrete implementation of the Client interface that interacts
// directly with the database.
type DBClient struct {
	repo      db.Repository
	tree      *merkle.Tree
	publicKey []byte
}

// NewDBClient creates a new DBClient with the given database repository.
func NewDBClient(ctx context.Context, repo db.Repository, publicKey ed25519.PublicKey) (*DBClient, error) {
	entries, err := repo.GetAllTlogEntries(ctx)
	if err != nil {
		return nil, err
	}

	var leaves [][]byte
	for _, entry := range entries {
		leaves = append(leaves, entry.SignedMessage)
	}

	tree := merkle.NewTree(leaves)
	return &DBClient{
		repo:      repo,
		tree:      tree,
		publicKey: publicKey,
	}, nil
}

// SubmitMessage submits a message to the transparency log by inserting a new
// entry into the tlog_entries table.
func (c *DBClient) SubmitMessage(ctx context.Context, message []byte) (string, error) {
	c.tree.AddLeaf(message)
	merkleRoot := c.tree.MerkleRoot()
	publicKeyHash := sha256.Sum256(c.publicKey)

	if err := c.repo.AddTlogEntry(ctx, merkleRoot, message, publicKeyHash[:]); err != nil {
		return "", err
	}

	return hex.EncodeToString(merkleRoot), nil
}
