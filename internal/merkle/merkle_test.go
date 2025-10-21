// Package merkle provides a Merkle tree implementation.
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMerkleTree(t *testing.T) {
	t.Run("creates an empty tree", func(t *testing.T) {
		tree := NewTree([][]byte{})
		assert.Nil(t, tree.MerkleRoot())
	})

	t.Run("creates a tree with one leaf", func(t *testing.T) {
		data := [][]byte{[]byte("leaf1")}
		tree := NewTree(data)
		hash := sha256.Sum256(data[0])
		assert.Equal(t, hash[:], tree.MerkleRoot())
	})

	t.Run("calculates correct root for two leaves", func(t *testing.T) {
		data := [][]byte{[]byte("leaf1"), []byte("leaf2")}
		tree := NewTree(data)
		h1 := sha256.Sum256(data[0])
		h2 := sha256.Sum256(data[1])
		combined := append(h1[:], h2[:]...)
		expectedRoot := sha256.Sum256(combined)
		assert.Equal(t, expectedRoot[:], tree.MerkleRoot())
	})

	t.Run("calculates correct root for three leaves", func(t *testing.T) {
		l1, l2, l3 := []byte("leaf1"), []byte("leaf2"), []byte("leaf3")
		tree := NewTree([][]byte{})
		tree.AddLeaf(l1)
		tree.AddLeaf(l2)
		tree.AddLeaf(l3)

		// Calculate expected root
		h1 := sha256.Sum256(l1)
		h2 := sha256.Sum256(l2)
		h3 := sha256.Sum256(l3)

		// Level 1
		p1 := sha256.Sum256(append(h1[:], h2[:]...))
		p2 := sha256.Sum256(append(h3[:], h3[:]...)) // p2 is hash of l3 with itself

		// Level 2 (Root)
		root := sha256.Sum256(append(p1[:], p2[:]...))

		assert.Equal(t, hex.EncodeToString(root[:]), hex.EncodeToString(tree.MerkleRoot()))
	})

	t.Run("calculates correct root for four leaves", func(t *testing.T) {
		l1, l2, l3, l4 := []byte("leaf1"), []byte("leaf2"), []byte("leaf3"), []byte("leaf4")
		tree := NewTree([][]byte{l1, l2, l3, l4})

		// Calculate expected root
		h1 := sha256.Sum256(l1)
		h2 := sha256.Sum256(l2)
		h3 := sha256.Sum256(l3)
		h4 := sha256.Sum256(l4)

		// Level 1
		p1 := sha256.Sum256(append(h1[:], h2[:]...))
		p2 := sha256.Sum256(append(h3[:], h4[:]...))

		// Level 2 (Root)
		root := sha256.Sum256(append(p1[:], p2[:]...))

		assert.Equal(t, hex.EncodeToString(root[:]), hex.EncodeToString(tree.MerkleRoot()))
	})

	t.Run("rebuilds correctly after adding leaves one by one", func(t *testing.T) {
		tree := NewTree([][]byte{})

		// 1. Add leaf1
		l1 := []byte("leaf1")
		tree.AddLeaf(l1)
		h1 := sha256.Sum256(l1)
		assert.Equal(t, h1[:], tree.MerkleRoot(), "Root should be hash of leaf1")

		// 2. Add leaf2
		l2 := []byte("leaf2")
		tree.AddLeaf(l2)
		h2 := sha256.Sum256(l2)
		p1 := sha256.Sum256(append(h1[:], h2[:]...))
		assert.Equal(t, p1[:], tree.MerkleRoot(), "Root should be hash of (h1, h2)")

		// 3. Add leaf3
		l3 := []byte("leaf3")
		tree.AddLeaf(l3)
		h3 := sha256.Sum256(l3)
		p2 := sha256.Sum256(append(h3[:], h3[:]...))
		root := sha256.Sum256(append(p1[:], p2[:]...))
		assert.Equal(t, root[:], tree.MerkleRoot(), "Root should be hash of (p1, p2)")
	})
}
