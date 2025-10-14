package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/fedi-e2ee/pkd-server-go/internal/config"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"zntr.io/paseto/v4"
)

// TokenService is an interface for managing PASETO tokens.
type TokenService interface {
	// NewPair creates a new access token and refresh token pair.
	NewPair() (accessToken, refreshToken string, err error)
	// ValidateAccessToken validates an access token and returns its claims.
	ValidateAccessToken(token string) (map[string]interface{}, error)
	// ValidateRefreshToken validates a refresh token and returns its claims.
	ValidateRefreshToken(token string) (map[string]interface{}, error)
	// Refresh refreshes an access token using a refresh token. It returns a new
	// access token and a new refresh token.
	Refresh(refreshToken string) (newAccessToken, newRefreshToken string, err error)
}

// pasetoTokenService is an implementation of TokenService that uses PASETO v4 local tokens.
type pasetoTokenService struct {
	keyManager KeyManager
	config     *config.Config
	db         *sqlx.DB
}

// NewPasetoTokenService creates a new pasetoTokenService.
func NewPasetoTokenService(keyManager KeyManager, cfg *config.Config, db *sqlx.DB) TokenService {
	return &pasetoTokenService{
		keyManager: keyManager,
		config:     cfg,
		db:         db,
	}
}

// NewPair creates a new access token and refresh token pair.
func (s *pasetoTokenService) NewPair() (string, string, error) {
	// Create the access token.
	accessToken, err := s.newAccessToken()
	if err != nil {
		return "", "", err
	}

	// Create the refresh token.
	refreshToken, err := s.newRefreshToken()
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// ValidateAccessToken validates an access token and returns its claims.
func (s *pasetoTokenService) ValidateAccessToken(tokenStr string) (map[string]interface{}, error) {
	return s.validateToken(tokenStr, "access")
}

// ValidateRefreshToken validates a refresh token and returns its claims.
func (s *pasetoTokenService) ValidateRefreshToken(tokenStr string) (map[string]interface{}, error) {
	claims, err := s.validateToken(tokenStr, "refresh")
	if err != nil {
		return nil, err
	}

	// Check if the refresh token has been used.
	jti, ok := claims["jti"].(string)
	if !ok {
		return nil, errors.New("missing jti in refresh token")
	}

	var exists bool
	err = s.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM used_refresh_tokens WHERE jti = $1)", jti)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if exists {
		return nil, errors.New("refresh token has already been used")
	}

	return claims, nil
}

// Refresh refreshes an access token using a refresh token.
func (s *pasetoTokenService) Refresh(refreshToken string) (string, string, error) {
	claims, err := s.ValidateRefreshToken(refreshToken)
	if err != nil {
		return "", "", err
	}

	// Mark the refresh token as used.
	jti, ok := claims["jti"].(string)
	if !ok {
		return "", "", errors.New("missing jti in refresh token")
	}
	_, err = s.db.Exec("INSERT INTO used_refresh_tokens (jti) VALUES ($1)", jti)
	if err != nil {
		return "", "", err
	}

	// Create a new token pair.
	return s.NewPair()
}

// newAccessToken creates a new access token.
func (s *pasetoTokenService) newAccessToken() (string, error) {
	now := time.Now()
	claims := map[string]interface{}{
		"pkd-admin": true,
		"token-type": "access",
	}
	return s.newToken(claims, now, 15*time.Minute)
}

// newRefreshToken creates a new refresh token.
func (s *pasetoTokenService) newRefreshToken() (string, error) {
	now := time.Now()
	claims := map[string]interface{}{
		"token-type": "refresh",
	}
	return s.newToken(claims, now, 12*time.Hour)
}

// newToken creates a new PASETO v4 local token with the given claims.
func (s *pasetoTokenService) newToken(claims map[string]interface{}, now time.Time, ttl time.Duration) (string, error) {
	keyBytes, err := s.keyManager.GetPasetoSymmetricKey()
	if err != nil {
		return "", err
	}
	key, err := v4.LocalKeyFromSeed(keyBytes)
	if err != nil {
		return "", err
	}

	jti, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	// Add standard claims to the map
	claims["iss"] = s.config.Server.Host
	claims["jti"] = jti.String()
	claims["iat"] = now.Format(time.RFC3339)
	claims["exp"] = now.Add(ttl).Format(time.RFC3339)
	claims["nbf"] = now.Format(time.RFC3339)

	// Marshal the claims to JSON.
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	return v4.Encrypt(rand.Reader, key, payload, nil, nil)
}

// validateToken validates a token and returns its claims.
func (s *pasetoTokenService) validateToken(tokenStr, tokenType string) (map[string]interface{}, error) {
	keyBytes, err := s.keyManager.GetPasetoSymmetricKey()
	if err != nil {
		return nil, err
	}
	key, err := v4.LocalKeyFromSeed(keyBytes)
	if err != nil {
		return nil, err
	}

	payload, err := v4.Decrypt(key, tokenStr, nil, nil)
	if err != nil {
		return nil, err
	}

	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	if err != nil {
		return nil, err
	}

	// Manual validation of standard claims.
	expStr, ok := claims["exp"].(string)
	if !ok {
		return nil, errors.New("missing exp claim")
	}
	exp, err := time.Parse(time.RFC3339, expStr)
	if err != nil {
		return nil, errors.New("invalid exp claim")
	}
	if time.Now().After(exp) {
		return nil, errors.New("token has expired")
	}

	// Check the token type.
	if claims["token-type"] != tokenType {
		return nil, errors.New("invalid token type")
	}

	return claims, nil
}
