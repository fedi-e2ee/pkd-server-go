package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/fedi-e2ee/pkd-server-go/internal/auth"
	"github.com/fedi-e2ee/pkd-server-go/internal/config"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthMiddleware(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer func() {
		_ = db.Close()
	}()
	sqlxDB := sqlx.NewDb(db, "sqlmock")

	t.Run("NoPassword_DefaultService_ShouldSucceed", func(t *testing.T) {
		keyFilePath := t.TempDir() + "/test.key"
		cfg := &config.Config{Server: config.Server{Host: "localhost", KeyFile: config.KeyFile{
			Path:            keyFilePath,
			Argon2idTime:    1,
			Argon2idMemory:  1024,
			Argon2idThreads: 1,
		}}}

		// Mimic server startup: create KM and TS with no password
		km, err := auth.NewFileKeyManager(keyFilePath, []byte("default"), 1, 1024, 1)
		require.NoError(t, err)
		ts := auth.NewPasetoTokenService(km, cfg, sqlxDB)

		s := &Server{config: cfg, tokenService: ts, db: sqlxDB}
		handler := s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Create a token with the default service
		accessToken, _, err := ts.NewPair()
		require.NoError(t, err)

		// Make request, should succeed
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("WithPassword_NoHeader_ShouldFail", func(t *testing.T) {
		keyFilePath := t.TempDir() + "/test.key"
		password := []byte("password")
		cfg := &config.Config{Server: config.Server{Host: "localhost", KeyFile: config.KeyFile{
			Path:            keyFilePath,
			Argon2idTime:    1,
			Argon2idMemory:  1024,
			Argon2idThreads: 1,
		}}}

		// Create a token with a password-protected key. This creates the file on disk.
		kmWithPwd, err := auth.NewFileKeyManager(keyFilePath, password, 1, 1024, 1)
		require.NoError(t, err)
		tsWithPwd := auth.NewPasetoTokenService(kmWithPwd, cfg, sqlxDB)
		accessToken, _, err := tsWithPwd.NewPair()
		require.NoError(t, err)

		// Mimic server startup: create default KM and TS *without* the password.
		// It points to the same file, but the service doesn't know the password.
		kmNoPwd, err := auth.NewFileKeyManager(keyFilePath, []byte("default"), 1, 1024, 1)
		require.NoError(t, err)
		tsNoPwd := auth.NewPasetoTokenService(kmNoPwd, cfg, sqlxDB)

		s := &Server{config: cfg, tokenService: tsNoPwd, db: sqlxDB}
		handler := s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Make request with password-protected token, but no header.
		// The default tsNoPwd will be used, and it will fail to decrypt the key file.
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("WithPassword_CorrectHeader_ShouldSucceed", func(t *testing.T) {
		keyFilePath := t.TempDir() + "/test.key"
		password := []byte("password-A")
		cfg := &config.Config{Server: config.Server{Host: "localhost", KeyFile: config.KeyFile{
			Path:            keyFilePath,
			Argon2idTime:    1,
			Argon2idMemory:  1024,
			Argon2idThreads: 1,
		}}}

		// Create a token with a password-protected key.
		kmWithPwd, err := auth.NewFileKeyManager(keyFilePath, password, 1, 1024, 1)
		require.NoError(t, err)
		tsWithPwd := auth.NewPasetoTokenService(kmWithPwd, cfg, sqlxDB)
		accessToken, _, err := tsWithPwd.NewPair()
		require.NoError(t, err)

		// Mimic server startup with a default service that cannot read the key file.
		kmNoPwd, err := auth.NewFileKeyManager(keyFilePath, []byte("default"), 1, 1024, 1)
		require.NoError(t, err)
		tsNoPwd := auth.NewPasetoTokenService(kmNoPwd, cfg, sqlxDB)

		s := &Server{config: cfg, tokenService: tsNoPwd, db: sqlxDB}
		handler := s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Make request with password-protected token AND correct header.
		// The middleware should create a new KM with the password and succeed.
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("X-PKD-Key-Password", string(password))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("WithPassword_IncorrectHeader_ShouldFail", func(t *testing.T) {
		keyFilePath := t.TempDir() + "/test.key"
		passwordA := []byte("password-A")
		passwordB := []byte("password-B")
		cfg := &config.Config{Server: config.Server{Host: "localhost", KeyFile: config.KeyFile{
			Path:            keyFilePath,
			Argon2idTime:    1,
			Argon2idMemory:  1024,
			Argon2idThreads: 1,
		}}}

		// Create a token with password-A.
		kmWithPwd, err := auth.NewFileKeyManager(keyFilePath, passwordA, 1, 1024, 1)
		require.NoError(t, err)
		tsWithPwd := auth.NewPasetoTokenService(kmWithPwd, cfg, sqlxDB)
		accessToken, _, err := tsWithPwd.NewPair()
		require.NoError(t, err)

		// Mimic server startup with a default service that cannot read the key file.
		kmNoPwd, err := auth.NewFileKeyManager(keyFilePath, []byte("default"), 1, 1024, 1)
		require.NoError(t, err)
		tsNoPwd := auth.NewPasetoTokenService(kmNoPwd, cfg, sqlxDB)

		s := &Server{config: cfg, tokenService: tsNoPwd, db: sqlxDB}
		handler := s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Make request with password-protected token AND INCORRECT header (password-B).
		// The middleware should create a new KM with the wrong password and fail.
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("X-PKD-Key-Password", string(passwordB))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}
