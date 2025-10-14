package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// GenerateKeyID creates a new, random 256-bit key identifier, encoded as base64url.
func GenerateKeyID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes for key-id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// HashBytes computes the SHA-256 hash of a byte slice and returns it as a hex-encoded string.
func HashBytes(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
