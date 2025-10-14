package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"

	"golang.org/x/crypto/argon2"
)

// KeyManager is an interface for managing the cryptographic keys used for
// signing and encrypting PASETO tokens.
type KeyManager interface {
	GetPasetoSymmetricKey() ([]byte, error)
}

// fileKeyManager is an implementation of KeyManager that stores the key
// in a file on disk. The key is encrypted at rest using a password and
// Argon2id for key derivation.
type fileKeyManager struct {
	keyFilePath     string
	password        []byte
	argon2idTime    uint32
	argon2idMemory  uint32
	argon2idThreads uint8
}

// NewFileKeyManager creates a new fileKeyManager. If the key file does not
// exist or is empty, it will be created with a new random key.
func NewFileKeyManager(keyFilePath string, password []byte, time, memory uint32, threads uint8) (KeyManager, error) {
	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}
	km := &fileKeyManager{
		keyFilePath:     keyFilePath,
		password:        password,
		argon2idTime:    time,
		argon2idMemory:  memory,
		argon2idThreads: threads,
	}

	// If the key file doesn't exist or is empty, create it with a new key.
	info, err := os.Stat(keyFilePath)
	if os.IsNotExist(err) || (err == nil && info.Size() == 0) {
		if err := km.generateAndSaveKey(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	return km, nil
}

// GetPasetoSymmetricKey retrieves the PASETO symmetric key from the key file.
func (km *fileKeyManager) GetPasetoSymmetricKey() ([]byte, error) {
	data, err := os.ReadFile(km.keyFilePath)
	if err != nil {
		return nil, err
	}

	parts := bytes.Split(data, []byte(":"))
	if len(parts) != 2 {
		return nil, errors.New("invalid key file format")
	}

	salt, err := base64.RawURLEncoding.DecodeString(string(parts[0]))
	if err != nil {
		return nil, err
	}
	encryptedKey, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return nil, err
	}

	// Derive the key and nonce from the password and salt.
	derivedKey := argon2.IDKey(km.password, salt, km.argon2idTime, km.argon2idMemory, km.argon2idThreads, 44)
	key := derivedKey[:32]
	nonce := derivedKey[32:]

	// Decrypt the key using AES-GCM.
	return decryptWithAESGCM(encryptedKey, key, nonce, salt)
}

// generateAndSaveKey creates a new random key and saves it to the key file.
func (km *fileKeyManager) generateAndSaveKey() error {
	// Generate a new 32-byte random key.
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return err
	}

	// Generate a random salt.
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	// Derive the encryption key and nonce from the password and salt.
	derivedKey := argon2.IDKey(km.password, salt, km.argon2idTime, km.argon2idMemory, km.argon2idThreads, 44)
	encryptionKey := derivedKey[:32]
	nonce := derivedKey[32:]

	// Encrypt the new key with the derived key.
	encryptedKey, err := encryptWithAESGCM(newKey, encryptionKey, nonce, salt)
	if err != nil {
		return err
	}

	// Save the salt and encrypted key to the file.
	saltB64 := base64.RawURLEncoding.EncodeToString(salt)
	encryptedKeyB64 := base64.RawURLEncoding.EncodeToString(encryptedKey)
	data := []byte(saltB64 + ":" + encryptedKeyB64)

	return os.WriteFile(km.keyFilePath, data, 0600)
}
