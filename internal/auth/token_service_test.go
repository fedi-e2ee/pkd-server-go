package auth

import (
	"database/sql"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/fedi-e2ee/pkd-server-go/internal/config"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKeyManager is a mock implementation of the KeyManager interface.
type mockKeyManager struct {
	key []byte
}

func (m *mockKeyManager) GetPasetoSymmetricKey() ([]byte, error) {
	return m.key, nil
}

func newMockKeyManager() *mockKeyManager {
	return &mockKeyManager{
		key: []byte("test-key-for-paseto-v4-tokens-12"),
	}
}

func TestPasetoTokenService(t *testing.T) {
	km := newMockKeyManager()
	cfg := &config.Config{
		Server: config.Server{
			Host: "localhost",
		},
	}

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() {
		_ = db.Close()
	}()
	sqlxDB := sqlx.NewDb(db, "sqlmock")

	ts := NewPasetoTokenService(km, cfg, sqlxDB)

	t.Run("NewPair", func(t *testing.T) {
		accessToken, refreshToken, err := ts.NewPair()
		require.NoError(t, err)
		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, refreshToken)
	})

	t.Run("ValidateAccessToken", func(t *testing.T) {
		accessToken, _, err := ts.NewPair()
		require.NoError(t, err)

		claims, err := ts.ValidateAccessToken(accessToken)
		require.NoError(t, err)
		assert.Equal(t, true, claims["pkd-admin"])
		assert.Equal(t, "access", claims["token-type"])
	})

	t.Run("ValidateAccessToken_InvalidToken", func(t *testing.T) {
		_, err := ts.ValidateAccessToken("invalid-token")
		assert.Error(t, err)
	})

	t.Run("ValidateRefreshToken", func(t *testing.T) {
		_, refreshToken, err := ts.NewPair()
		require.NoError(t, err)

		mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS(SELECT 1 FROM used_refresh_tokens WHERE jti = $1)`)).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

		claims, err := ts.ValidateRefreshToken(refreshToken)
		require.NoError(t, err)
		assert.Equal(t, "refresh", claims["token-type"])
	})

	t.Run("ValidateAccessToken_Expired", func(t *testing.T) {
		pasetoService := ts.(*pasetoTokenService)
		token, err := pasetoService.newToken(map[string]interface{}{"token-type": "access"}, time.Now().Add(-1*time.Hour), 15*time.Minute)
		require.NoError(t, err)

		_, err = pasetoService.ValidateAccessToken(token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has expired")
	})

	t.Run("ValidateRefreshToken_Expired", func(t *testing.T) {
		pasetoService := ts.(*pasetoTokenService)
		token, err := pasetoService.newToken(map[string]interface{}{"token-type": "refresh"}, time.Now().Add(-24*time.Hour), 12*time.Hour)
		require.NoError(t, err)

		_, err = pasetoService.ValidateRefreshToken(token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has expired")
	})

	t.Run("ValidateToken_InvalidType", func(t *testing.T) {
		accessToken, _, err := ts.NewPair()
		require.NoError(t, err)

		_, err = ts.(*pasetoTokenService).validateToken(accessToken, "invalid-type")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token type")
	})

	t.Run("Refresh", func(t *testing.T) {
		_, refreshToken, err := ts.NewPair()
		require.NoError(t, err)

		mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS(SELECT 1 FROM used_refresh_tokens WHERE jti = $1)`)).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
		mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO used_refresh_tokens (jti) VALUES ($1)`)).
			WillReturnResult(sqlmock.NewResult(1, 1))

		newAccessToken, newRefreshToken, err := ts.Refresh(refreshToken)
		require.NoError(t, err)
		assert.NotEmpty(t, newAccessToken)
		assert.NotEmpty(t, newRefreshToken)
	})

	t.Run("Refresh_UsedToken", func(t *testing.T) {
		_, refreshToken, err := ts.NewPair()
		require.NoError(t, err)

		mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS(SELECT 1 FROM used_refresh_tokens WHERE jti = $1)`)).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

		_, _, err = ts.Refresh(refreshToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "refresh token has already been used")
	})

	t.Run("Refresh_DBError", func(t *testing.T) {
		_, refreshToken, err := ts.NewPair()
		require.NoError(t, err)

		mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS(SELECT 1 FROM used_refresh_tokens WHERE jti = $1)`)).
			WillReturnError(sql.ErrConnDone)

		_, _, err = ts.Refresh(refreshToken)
		assert.Error(t, err)
		assert.Equal(t, sql.ErrConnDone, err)
	})
}
