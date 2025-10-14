package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/fedi-e2ee/pkd-server-go/internal/auth"
)

type contextKey string

const userContextKey = contextKey("user")

// authMiddleware is a middleware that checks for a valid PASETO access token
// in the Authorization header.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the Authorization header.
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.respondWithError(w, http.StatusUnauthorized, "Missing Authorization header")
			return
		}

		// The header should be in the format "Bearer <token>".
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			s.respondWithError(w, http.StatusUnauthorized, "Invalid Authorization header format")
			return
		}
		token := parts[1]

		// If the X-PKD-Key-Password header is present, use it to create a new
		// token service for this request.
		var claims map[string]interface{}
		var err error
		if password := r.Header.Get("X-PKD-Key-Password"); password != "" {
			km, err := auth.NewFileKeyManager(
				s.config.Server.KeyFile.Path,
				[]byte(password),
				s.config.Server.KeyFile.Argon2idTime,
				s.config.Server.KeyFile.Argon2idMemory,
				s.config.Server.KeyFile.Argon2idThreads,
			)
			if err != nil {
				s.respondWithError(w, http.StatusInternalServerError, "Failed to create key manager: "+err.Error())
				return
			}
			ts := auth.NewPasetoTokenService(km, s.config, s.db)
			claims, err = ts.ValidateAccessToken(token)
			if err != nil {
				s.respondWithError(w, http.StatusUnauthorized, "Invalid access token: "+err.Error())
				return
			}
		} else {
			claims, err = s.tokenService.ValidateAccessToken(token)
		}

		if err != nil {
			s.respondWithError(w, http.StatusUnauthorized, "Invalid access token: "+err.Error())
			return
		}

		// Check for the "pkd-admin" claim.
		isAdmin, ok := claims["pkd-admin"].(bool)
		if !ok || !isAdmin {
			s.respondWithError(w, http.StatusForbidden, "Not an admin token")
			return
		}

		// Add the claims to the request context.
		ctx := context.WithValue(r.Context(), userContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
