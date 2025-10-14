package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
)

var (
	// ErrInvalidSignature is returned when a signature is invalid.
	ErrInvalidSignature = errors.New("invalid signature")
	// ErrInvalidPublicKey is returned when a public key is malformed.
	ErrInvalidPublicKey = errors.New("invalid public key")
	// ErrInvalidSecretKey is returned when a secret key is malformed.
	ErrInvalidSecretKey = errors.New("invalid secret key")
)

const (
	ed25519Prefix = "ed25519:"
)



// SignMessage signs a SignedMessage struct and returns the base64url-encoded signature.
func SignMessage(privateKey ed25519.PrivateKey, msgToSign []byte) (string, error) {
	signature := ed25519.Sign(privateKey, msgToSign)
	return base64.RawURLEncoding.EncodeToString(signature), nil
}

// VerifyMessageSignature verifies the signature of a protocol message.
func VerifyMessageSignature(msg *protocol.ProtocolMessage, publicKey ed25519.PublicKey) error {
	// Reconstruct the message that was signed
	signedMsg := protocol.SignedMessage{
		PKDContext:       msg.PKDContext,
		Action:           msg.Action,
		Message:          msg.Message,
		RecentMerkleRoot: msg.RecentMerkleRoot,
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal signed message for verification: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(msg.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	if !ed25519.Verify(publicKey, signedMsgBytes, sig) {
		return ErrInvalidSignature
	}

	return nil
}

// EncodePublicKey encodes a public key into the "ed25519:<base64url>" format.
func EncodePublicKey(pk ed25519.PublicKey) string {
	return ed25519Prefix + base64.RawURLEncoding.EncodeToString(pk)
}

// EncodePrivateKey encodes a private key into a base64url-encoded string.
func EncodePrivateKey(sk ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(sk)
}

// DecodePublicKey decodes a public key from the "ed25519:<base64url>" format.
func DecodePublicKey(pkStr string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(pkStr, ed25519Prefix) {
		return nil, fmt.Errorf("%w: missing prefix", ErrInvalidPublicKey)
	}
	pkBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(pkStr, ed25519Prefix))
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode failed: %v", ErrInvalidPublicKey, err)
	}
	if len(pkBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid length", ErrInvalidPublicKey)
	}
	return ed25519.PublicKey(pkBytes), nil
}

// DecodeSecretKey decodes a secret key from a base64url-encoded string.
func DecodeSecretKey(skStr string) (ed25519.PrivateKey, error) {
	skBytes, err := base64.RawURLEncoding.DecodeString(skStr)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode failed: %v", ErrInvalidSecretKey, err)
	}
	if len(skBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: invalid length", ErrInvalidSecretKey)
	}
	return ed25519.PrivateKey(skBytes), nil
}

// GeneratePrivateKey generates a new ed25519 private key.
func GeneratePrivateKey() (ed25519.PrivateKey, error) {
	_, sk, err := ed25519.GenerateKey(nil)
	return sk, err
}
