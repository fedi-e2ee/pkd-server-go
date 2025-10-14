package api

import (
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fedi-e2ee/pkd-server-go/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestServer_respondWithError(t *testing.T) {
	// setup
	server := &Server{
		logger: log.New(io.Discard, "", 0),
	}
	res := httptest.NewRecorder()

	// exercise
	server.respondWithError(res, http.StatusBadRequest, "error message")

	// assert
	assert.Equal(t, http.StatusBadRequest, res.Code)
	expectedJSON := `{
		"type": "about:blank",
		"title": "Bad Request",
		"status": 400,
		"detail": "error message"
	}`
	assert.JSONEq(t, expectedJSON, res.Body.String())
}

func TestServer_respondWithJSON(t *testing.T) {
	t.Run("returns marshaled JSON", func(t *testing.T) {
		// setup
		server := &Server{
			logger: log.New(io.Discard, "", 0),
		}
		res := httptest.NewRecorder()
		payload := map[string]string{"key": "value"}

		// exercise
		server.respondWithJSON(res, http.StatusOK, payload)

		// assert
		assert.Equal(t, http.StatusOK, res.Code)
		assert.JSONEq(t, `{"key":"value"}`, res.Body.String())
	})

	t.Run("returns error if payload cannot be marshaled", func(t *testing.T) {
		// setup
		server := &Server{
			logger: log.New(io.Discard, "", 0),
		}
		res := httptest.NewRecorder()
		payload := make(chan int)

		// exercise
		server.respondWithJSON(res, http.StatusOK, payload)

		// assert
		assert.Equal(t, http.StatusInternalServerError, res.Code)
		expectedJSON := `{
			"type": "about:blank",
			"title": "Internal Server Error",
			"status": 500,
			"detail": "Internal Server Error"
		}`
		assert.JSONEq(t, expectedJSON, res.Body.String())
	})
}

func TestServer_getDirectoryPublicKey(t *testing.T) {
	t.Run("returns public key if peer is found", func(t *testing.T) {
		// setup
		publicKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		server := &Server{
			logger: log.New(io.Discard, "", 0),
			config: &config.Config{
				Peers: map[string]config.Peer{
					"directory-url": {
						PublicKey: publicKey,
					},
				},
			},
		}

		// exercise
		key, err := server.getDirectoryPublicKey("directory-url")

		// assert
		assert.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("returns an error if peer is not found", func(t *testing.T) {
		// setup
		server := &Server{
			logger: log.New(io.Discard, "", 0),
			config: &config.Config{
				Peers: map[string]config.Peer{},
			},
		}

		// exercise
		key, err := server.getDirectoryPublicKey("directory-url")

		// assert
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("returns error if public key cannot be decoded", func(t *testing.T) {
		// setup
		server := &Server{
			logger: log.New(io.Discard, "", 0),
			config: &config.Config{
				Peers: map[string]config.Peer{
					"directory-url": {
						PublicKey: "invalid-key",
					},
				},
			},
		}

		// exercise
		key, err := server.getDirectoryPublicKey("directory-url")

		// assert
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("returns error if public key size is invalid", func(t *testing.T) {
		// setup
		publicKey := base64.RawURLEncoding.EncodeToString([]byte("invalid-size"))
		server := &Server{
			logger: log.New(io.Discard, "", 0),
			config: &config.Config{
				Peers: map[string]config.Peer{
					"directory-url": {
						PublicKey: publicKey,
					},
				},
			},
		}

		// exercise
		key, err := server.getDirectoryPublicKey("directory-url")

		// assert
		assert.Error(t, err)
		assert.Nil(t, key)
	})
}
