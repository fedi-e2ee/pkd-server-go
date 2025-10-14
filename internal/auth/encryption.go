package auth

import (
	"crypto/aes"
	"crypto/cipher"
)

// encryptWithAESGCM encrypts the given plaintext using AES-GCM.
func encryptWithAESGCM(plaintext, key, nonce, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// decryptWithAESGCM decrypts the given ciphertext using AES-GCM.
func decryptWithAESGCM(ciphertext, key, nonce, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
