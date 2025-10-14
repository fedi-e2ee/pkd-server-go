package api

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	pkd_crypto "github.com/fedi-e2ee/pkd-server-go/internal/crypto"
)

// actorKeyCache stores actor public keys to avoid re-fetching them on every request.
var actorKeyCache = &sync.Map{}

// fetchActorPublicKey fetches and caches an actor's public key from their ID URL.
func fetchActorPublicKey(keyID string) (crypto.PublicKey, error) {
	// 1. Check the cache first.
	if key, ok := actorKeyCache.Load(keyID); ok {
		if pubKey, ok := key.(crypto.PublicKey); ok {
			return pubKey, nil
		}
	}

	// 2. If not in cache, fetch the actor document.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", keyID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for keyId '%s': %w", keyID, err)
	}
	req.Header.Set("Accept", "application/activity+json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch keyId '%s': %w", keyID, err)
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch keyId '%s': received status code %d", keyID, res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body for keyId '%s': %w", keyID, err)
	}

	// 3. Parse the actor's JSON to find the public key.
	var actor struct {
		PublicKey struct {
			PublicKeyPem string `json:"publicKeyPem"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(body, &actor); err != nil {
		return nil, fmt.Errorf("failed to unmarshal actor JSON for keyId '%s': %w", keyID, err)
	}
	if actor.PublicKey.PublicKeyPem == "" {
		return nil, fmt.Errorf("actor document for keyId '%s' does not contain a publicKeyPem", keyID)
	}

	// 4. Decode the public key.
	pubKey, err := pkd_crypto.DecodePublicKey(actor.PublicKey.PublicKeyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key for keyId '%s': %w", keyID, err)
	}

	// 5. Store in cache.
	actorKeyCache.Store(keyID, pubKey)
	return pubKey, nil
}

// parseSignatureHeader parses the comma-separated key-value pairs from the Signature header.
func parseSignatureHeader(header string) map[string]string {
	params := make(map[string]string)
	parts := strings.Split(header, ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			key := kv[0]
			value := strings.Trim(kv[1], `"`)
			params[key] = value
		}
	}
	return params
}
