package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// ProtocolVersion defines the interface for a protocol version.
type ProtocolVersion interface {
	GetVersionHeader() []byte
}

// ProtocolVersionV1 implements ProtocolVersion for version 1.
type ProtocolVersionV1 struct{}

// GetVersionHeader returns the 1-byte header for version 1.
func (v *ProtocolVersionV1) GetVersionHeader() []byte {
	return []byte{0x01}
}

// GetProtocolVersion returns the protocol version object for the given version ID.
func GetProtocolVersion(version byte) (ProtocolVersion, error) {
	switch version {
	case 0x01:
		return &ProtocolVersionV1{}, nil
	default:
		return nil, fmt.Errorf("unknown protocol version: %x", version)
	}
}

const (
	// Version 1 Constants from the specification
	kdfEncryptKeyInfo = "FediE2EE-v1-Compliance-Encryption-Key"
	kdfAuthKeyInfo    = "FediE2EE-v1-Compliance-Message-Auth-Key"
	kdfCommitSaltInfo = "FediE2EE-v1-Compliance-KDF-Salt"
	keyBytes          = 32
	nonceBytes        = 16

	// Argon2id parameters from the specification
	argon2Memory  = 16384
	argon2Time    = 3
	argon2Threads = 1
	argon2SaltLen = 16
	argon2KeyLen  = 32

	// Component lengths for parsing encrypted attributes
	versionLen    = 1
	randomLen     = 32
	commitmentLen = 32
	tagLen        = 32
)

var (
	// ErrDecryptionFailed is a generic error for when decryption fails for any reason.
	ErrDecryptionFailed = errors.New("attribute decryption failed")
)

// lenEncode encodes a byte slice with its 64-bit little-endian length prefix.
// This is different from preAuthEncode as it's for a single item.
func lenEncode(data []byte) []byte {
	encoded := make([]byte, 8+len(data))
	binary.LittleEndian.PutUint64(encoded, uint64(len(data)))
	copy(encoded[8:], data)
	return encoded
}

// commitPlaintext implements the Message Attribute Plaintext Commitment Algorithm.
func commitPlaintext(attributeName, plaintext, merkleRoot, salt []byte) []byte {
	// l = len(m) || m || len(a) || a || len(p) || p
	var l []byte
	l = append(l, lenEncode(merkleRoot)...)
	l = append(l, lenEncode(attributeName)...)
	l = append(l, lenEncode(plaintext)...)

	// Q = PwKDF(password=l, salt=s)
	return argon2.IDKey(l, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
}

// EncryptAttribute implements the Message Attribute Encryption Algorithm.
func EncryptAttribute(attributeName, plaintext, ikm, merkleRoot []byte) ([]byte, error) {
	// 1. Set the version prefix h
	pv := &ProtocolVersionV1{}
	h := pv.GetVersionHeader()

	// 2. Generate 32 bytes of random data, r
	r := make([]byte, randomLen)
	if _, err := io.ReadFull(rand.Reader, r); err != nil {
		return nil, fmt.Errorf("failed to generate random data: %w", err)
	}

	// 3. Derive an encryption key, Ek, and nonce, n
	kdf := hkdf.New(sha512.New, ikm, nil, buildInfo(kdfEncryptKeyInfo, h, r, attributeName))
	derivedKey := make([]byte, keyBytes+nonceBytes)
	if _, err := io.ReadFull(kdf, derivedKey); err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}
	ek := derivedKey[:keyBytes]
	n := derivedKey[keyBytes:]

	// 4. Derive an authentication key, Ak
	kdf = hkdf.New(sha512.New, ikm, nil, buildInfo(kdfAuthKeyInfo, h, r, attributeName))
	ak := make([]byte, keyBytes)
	if _, err := io.ReadFull(kdf, ak); err != nil {
		return nil, fmt.Errorf("failed to derive authentication key: %w", err)
	}

	// 5. Derive a commitment salt, s
	saltHasher := sha512.New()
	saltHasher.Write([]byte(kdfCommitSaltInfo))
	saltHasher.Write(h)
	saltHasher.Write(r)
	saltHasher.Write(lenEncode(merkleRoot))
	saltHasher.Write(lenEncode(attributeName))
	s := saltHasher.Sum(nil)[:argon2SaltLen] // Truncate to 128 bits (16 bytes)

	// 6. Calculate a commitment of the plaintext, Q
	q := commitPlaintext(attributeName, plaintext, merkleRoot, s)

	// 7. Encrypt the plaintext attribute to obtain ciphertext, c
	block, err := aes.NewCipher(ek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	stream := cipher.NewCTR(block, n)
	c := make([]byte, len(plaintext))
	stream.XORKeyStream(c, plaintext)

	// 8. Calculate the MAC, t
	mac := hmac.New(sha512.New, ak)
	mac.Write(h)
	mac.Write(r)
	mac.Write(lenEncode(attributeName))
	mac.Write(lenEncode(c))
	mac.Write(lenEncode(q))
	// Truncate to the rightmost 256 bits (32 bytes)
	fullTag := mac.Sum(nil)
	t := fullTag[len(fullTag)-tagLen:]

	// 9. Return h || r || Q || t || c
	var result []byte
	result = append(result, h...)
	result = append(result, r...)
	result = append(result, q...)
	result = append(result, t...)
	result = append(result, c...)
	return result, nil
}

// DecryptAttribute implements the Message Attribute Decryption Algorithm.
func DecryptAttribute(attributeName, ciphertext, ikm, merkleRoot []byte) ([]byte, error) {
	// 1. Decompose input
	if len(ciphertext) < versionLen+randomLen+commitmentLen+tagLen {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrDecryptionFailed)
	}
	pos := 0
	h := ciphertext[pos : pos+versionLen]
	pos += versionLen
	r := ciphertext[pos : pos+randomLen]
	pos += randomLen
	q := ciphertext[pos : pos+commitmentLen]
	pos += commitmentLen
	t := ciphertext[pos : pos+tagLen]
	pos += tagLen
	c := ciphertext[pos:]

	// 2. Ensure h is equal to the expected version prefix
	_, err := GetProtocolVersion(h[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// 3. Derive an authentication key, Ak
	kdf := hkdf.New(sha512.New, ikm, nil, buildInfo(kdfAuthKeyInfo, h, r, attributeName))
	ak := make([]byte, keyBytes)
	if _, err := io.ReadFull(kdf, ak); err != nil {
		return nil, fmt.Errorf("%w: failed to derive auth key: %v", ErrDecryptionFailed, err)
	}

	// 4. Recalculate the MAC, t2
	mac := hmac.New(sha512.New, ak)
	mac.Write(h)
	mac.Write(r)
	mac.Write(lenEncode(attributeName))
	mac.Write(lenEncode(c))
	mac.Write(lenEncode(q))
	fullTag := mac.Sum(nil)
	t2 := fullTag[len(fullTag)-tagLen:]

	// 5. Compare t with t2 in constant time
	if subtle.ConstantTimeCompare(t, t2) != 1 {
		return nil, fmt.Errorf("%w: invalid authentication tag", ErrDecryptionFailed)
	}

	// 6. Derive an encryption key, Ek, and nonce, n
	kdf = hkdf.New(sha512.New, ikm, nil, buildInfo(kdfEncryptKeyInfo, h, r, attributeName))
	derivedKey := make([]byte, keyBytes+nonceBytes)
	if _, err := io.ReadFull(kdf, derivedKey); err != nil {
		return nil, fmt.Errorf("%w: failed to derive encryption key: %v", ErrDecryptionFailed, err)
	}
	ek := derivedKey[:keyBytes]
	n := derivedKey[keyBytes:]

	// 7. Decrypt c to obtain the message attribute value, p
	block, err := aes.NewCipher(ek)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create AES cipher: %v", ErrDecryptionFailed, err)
	}
	stream := cipher.NewCTR(block, n)
	p := make([]byte, len(c))
	stream.XORKeyStream(p, c)

	// 8. Derive a commitment salt, s
	saltHasher := sha512.New()
	saltHasher.Write([]byte(kdfCommitSaltInfo))
	saltHasher.Write(h)
	saltHasher.Write(r)
	saltHasher.Write(lenEncode(merkleRoot))
	saltHasher.Write(lenEncode(attributeName))
	s := saltHasher.Sum(nil)[:argon2SaltLen]

	// 9. Recalculate the commitment of the plaintext to obtain Q2
	q2 := commitPlaintext(attributeName, p, merkleRoot, s)

	// 10. Compare Q with Q2 in constant time
	if subtle.ConstantTimeCompare(q, q2) != 1 {
		return nil, fmt.Errorf("%w: plaintext commitment mismatch", ErrDecryptionFailed)
	}

	// 11. Return p
	return p, nil
}

// buildInfo constructs the info parameter for HKDF.
func buildInfo(context string, version, random, attributeName []byte) []byte {
	var info []byte
	info = append(info, []byte(context)...)
	info = append(info, version...)
	info = append(info, random...)
	info = append(info, lenEncode(attributeName)...)
	return info
}


// EncryptWithHPKE encrypts data using HPKE with the server's public key.
func EncryptWithHPKE(serverPublicKey kem.PublicKey, plaintext []byte) ([]byte, error) {
	// Use the recommended cipher suite
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)

	// Create a sender context
	sender, err := suite.NewSender(serverPublicKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HPKE sender: %w", err)
	}

	// Encapsulate and seal
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to setup HPKE sender: %w", err)
	}

	ciphertext, err := sealer.Seal(plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to seal plaintext with HPKE: %w", err)
	}

	// The final encrypted blob is the encapsulated key (enc) followed by the ciphertext.
	return append(enc, ciphertext...), nil
}

// DecryptWithHPKE decrypts data using HPKE with the server's private key.
func DecryptWithHPKE(serverPrivateKey kem.PrivateKey, encryptedData []byte) ([]byte, error) {
	// Use the recommended cipher suite
	kemID := hpke.KEM_X25519_HKDF_SHA256
	suite := hpke.NewSuite(kemID, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)

	// Determine the encapsulated key size from the KEM.
	encSize := kemID.Scheme().PublicKeySize()
	if len(encryptedData) < int(encSize) {
		return nil, fmt.Errorf("invalid encrypted data length")
	}

	enc := encryptedData[:encSize]
	ciphertext := encryptedData[encSize:]

	// Create a receiver context
	receiver, err := suite.NewReceiver(serverPrivateKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HPKE receiver: %w", err)
	}

	// Open the sealed message
	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, fmt.Errorf("failed to setup HPKE receiver: %w", err)
	}

	plaintext, err := opener.Open(ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open HPKE sealed message: %w", err)
	}

	return plaintext, nil
}
