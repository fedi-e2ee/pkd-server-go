package auth

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileKeyManager(t *testing.T) {
	password := []byte("password")
	time := uint32(1)
	memory := uint32(64 * 1024)
	threads := uint8(4)

	t.Run("NewFileKeyManager_CreatesNewKey", func(t *testing.T) {
		keyFilePath := t.TempDir() + "/test.key"
		km, err := NewFileKeyManager(keyFilePath, password, time, memory, threads)
		require.NoError(t, err)
		assert.NotNil(t, km)

		// Check that the key file was created.
		_, err = os.Stat(keyFilePath)
		assert.NoError(t, err)
	})

	t.Run("GetPasetoSymmetricKey_RoundTrip", func(t *testing.T) {
		keyFilePath := t.TempDir() + "/test.key"
		// Create a new key manager, which should generate and save a key.
		km1, err := NewFileKeyManager(keyFilePath, password, time, memory, threads)
		require.NoError(t, err)

		// Get the key.
		key1, err := km1.GetPasetoSymmetricKey()
		require.NoError(t, err)
		assert.Len(t, key1, 32)

		// Create a second key manager using the same file and password.
		km2, err := NewFileKeyManager(keyFilePath, password, time, memory, threads)
		require.NoError(t, err)

		// Get the key again.
		key2, err := km2.GetPasetoSymmetricKey()
		require.NoError(t, err)

		// The keys should be the same.
		assert.Equal(t, key1, key2)
	})

	t.Run("NewFileKeyManager_EmptyPassword", func(t *testing.T) {
		keyFilePath := t.TempDir() + "/test.key"
		// Create a new key manager with an empty password.
		km, err := NewFileKeyManager(keyFilePath, []byte{}, time, memory, threads)
		require.NoError(t, err)
		assert.NotNil(t, km)

		// Get the key.
		key, err := km.GetPasetoSymmetricKey()
		require.NoError(t, err)
		assert.Len(t, key, 32)
	})

	t.Run("GetPasetoSymmetricKey_InvalidFileFormat", func(t *testing.T) {
		keyFilePath := t.TempDir() + "/test.key"
		// Create a corrupted key file.
		err := os.WriteFile(keyFilePath, []byte("invalid-format"), 0600)
		require.NoError(t, err)

		km, err := NewFileKeyManager(keyFilePath, password, time, memory, threads)
		require.NoError(t, err)

		_, err = km.GetPasetoSymmetricKey()
		assert.Error(t, err)
		assert.Equal(t, "invalid key file format", err.Error())
	})

	t.Run("GetPasetoSymmetricKey_WrongPassword", func(t *testing.T) {
		keyFilePath := t.TempDir() + "/test.key"
		// Create a key manager, which should generate and save a key with "password-A"
		_, err := NewFileKeyManager(keyFilePath, []byte("password-A"), time, memory, threads)
		require.NoError(t, err)

		// Create a second key manager using the same file but wrong password.
		km2, err := NewFileKeyManager(keyFilePath, []byte("password-B"), time, memory, threads)
		require.NoError(t, err) // NewFileKeyManager doesn't return an error if file exists

		// Get the key. This SHOULD fail.
		_, err = km2.GetPasetoSymmetricKey()

		// Assert that it returns an error.
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cipher: message authentication failed")
	})
}
