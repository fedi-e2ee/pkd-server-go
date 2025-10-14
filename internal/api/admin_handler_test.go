package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	domainmock "github.com/fedi-e2ee/pkd-server-go/internal/domain/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestServer_handleCryptoShred(t *testing.T) {
	t.Run("returns error if request body is not valid JSON", func(t *testing.T) {
		// setup
		service := new(domainmock.Service)
		server := &Server{
			service: service,
		}
		req := httptest.NewRequest(http.MethodPost, "/admin/crypto-shred", bytes.NewBuffer([]byte("invalid-json")))
		res := httptest.NewRecorder()

		// exercise
		server.handleCryptoShred(res, req)

		// assert
		assert.Equal(t, http.StatusBadRequest, res.Code)
		expectedJSON := `{
			"type": "about:blank",
			"title": "Bad Request",
			"status": 400,
			"detail": "Invalid JSON body"
		}`
		assert.JSONEq(t, expectedJSON, res.Body.String())
	})

	t.Run("returns error if actor-id is missing from request body", func(t *testing.T) {
		// setup
		service := new(domainmock.Service)
		server := &Server{
			service: service,
		}
		body, _ := json.Marshal(CryptoShredRequest{})
		req := httptest.NewRequest(http.MethodPost, "/admin/crypto-shred", bytes.NewBuffer(body))
		res := httptest.NewRecorder()

		// exercise
		server.handleCryptoShred(res, req)

		// assert
		assert.Equal(t, http.StatusBadRequest, res.Code)
		expectedJSON := `{
			"type": "about:blank",
			"title": "Bad Request",
			"status": 400,
			"detail": "Missing actor-id in request"
		}`
		assert.JSONEq(t, expectedJSON, res.Body.String())
	})

	t.Run("returns error if crypto-shredding fails", func(t *testing.T) {
		// setup
		service := new(domainmock.Service)
		service.On("CryptoShred", mock.Anything, "actor-id").Return(errors.New("crypto-shredding failed"))
		server := &Server{
			service: service,
		}
		body, _ := json.Marshal(CryptoShredRequest{
			ActorID: "actor-id",
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/crypto-shred", bytes.NewBuffer(body))
		res := httptest.NewRecorder()

		// exercise
		server.handleCryptoShred(res, req)

		// assert
		assert.Equal(t, http.StatusInternalServerError, res.Code)
		expectedJSON := `{
			"type": "about:blank",
			"title": "Internal Server Error",
			"status": 500,
			"detail": "Failed to crypto-shred actor: crypto-shredding failed"
		}`
		assert.JSONEq(t, expectedJSON, res.Body.String())
	})

	t.Run("does not return error if actor is not found", func(t *testing.T) {
		// setup
		service := new(domainmock.Service)
		service.On("CryptoShred", mock.Anything, "actor-id").Return(domain.ErrActorNotFound)
		server := &Server{
			service: service,
		}
		body, _ := json.Marshal(CryptoShredRequest{
			ActorID: "actor-id",
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/crypto-shred", bytes.NewBuffer(body))
		res := httptest.NewRecorder()

		// exercise
		server.handleCryptoShred(res, req)

		// assert
		assert.Equal(t, http.StatusOK, res.Code)
		assert.JSONEq(t, `{"status":"crypto-shredding completed","actor-id":"actor-id"}`, res.Body.String())
	})

	t.Run("returns success message if crypto-shredding succeeds", func(t *testing.T) {
		// setup
		service := new(domainmock.Service)
		service.On("CryptoShred", mock.Anything, "actor-id").Return(nil)
		server := &Server{
			service: service,
		}
		body, _ := json.Marshal(CryptoShredRequest{
			ActorID: "actor-id",
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/crypto-shred", bytes.NewBuffer(body))
		res := httptest.NewRecorder()

		// exercise
		server.handleCryptoShred(res, req)

		// assert
		assert.Equal(t, http.StatusOK, res.Code)
		assert.JSONEq(t, `{"status":"crypto-shredding completed","actor-id":"actor-id"}`, res.Body.String())
	})
}
