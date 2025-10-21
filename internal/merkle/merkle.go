// Package merkle provides a Merkle tree implementation.
package merkle

import (
	"crypto/sha256"
)

// Node represents a node in the Merkle tree.
type Node struct {
	Hash  []byte
	Left  *Node
	Right *Node
}

// Tree represents a Merkle tree.
type Tree struct {
	Root   *Node
	leaves []*Node
}

// NewTree creates a new Merkle tree from a slice of data.
func NewTree(data [][]byte) *Tree {
	var leaves []*Node
	for _, d := range data {
		hash := sha256.Sum256(d)
		leaves = append(leaves, &Node{Hash: hash[:]})
	}

	tree := &Tree{leaves: leaves}
	if len(leaves) > 0 {
		tree.Root = buildTree(leaves)
	}
	return tree
}

// buildTree recursively builds the Merkle tree from a slice of nodes.
func buildTree(nodes []*Node) *Node {
	if len(nodes) == 0 {
		return nil
	}
	if len(nodes) == 1 {
		return nodes[0]
	}

	var newLevel []*Node
	for i := 0; i < len(nodes); i += 2 {
		left := nodes[i]
		var right *Node
		if i+1 < len(nodes) {
			right = nodes[i+1]
		} else {
			// If there's an odd number of nodes, the last one is duplicated
			// to create its pair.
			right = left
		}
		combinedHash := append(left.Hash, right.Hash...)
		hash := sha256.Sum256(combinedHash)
		newLevel = append(newLevel, &Node{Hash: hash[:], Left: left, Right: right})
	}
	return buildTree(newLevel)
}

// AddLeaf adds a new leaf to the Merkle tree and recalculates the root.
func (t *Tree) AddLeaf(data []byte) {
	hash := sha256.Sum256(data)
	newNode := &Node{Hash: hash[:]}
	t.leaves = append(t.leaves, newNode)
	t.Root = buildTree(t.leaves)
}

// MerkleRoot returns the root hash of the tree.
func (t *Tree) MerkleRoot() []byte {
	if t.Root == nil {
		return nil
	}
	return t.Root.Hash
}
