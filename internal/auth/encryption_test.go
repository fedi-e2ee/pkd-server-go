package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESGCM(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	additionalData := make([]byte, 16)
	plaintext := []byte("test plaintext")

	// Successful encryption and decryption
	ciphertext, err := encryptWithAESGCM(plaintext, key, nonce, additionalData)
	require.NoError(t, err)

	decrypted, err := decryptWithAESGCM(ciphertext, key, nonce, additionalData)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Error case: invalid key
	_, err = encryptWithAESGCM(plaintext, []byte("invalid key"), nonce, additionalData)
	assert.Error(t, err)

	_, err = decryptWithAESGCM(ciphertext, []byte("invalid key"), nonce, additionalData)
	assert.Error(t, err)

	// Error case: tampered additional data
	_, err = decryptWithAESGCM(ciphertext, key, nonce, []byte("tampered"))
	assert.Error(t, err)

	// Error case: tampered ciphertext
	tamperedCiphertext := make([]byte, len(ciphertext))
	copy(tamperedCiphertext, ciphertext)
	tamperedCiphertext[0] ^= 0xff
	_, err = decryptWithAESGCM(tamperedCiphertext, key, nonce, additionalData)
	assert.Error(t, err)
}
