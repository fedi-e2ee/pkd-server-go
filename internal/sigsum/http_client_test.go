package sigsum

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHTTPClient_SubmitMessage(t *testing.T) {
	t.Run("successful submission", func(t *testing.T) {
		// Create a mock server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			// Read the request body
			body, err := io.ReadAll(r.Body)
			assert.NoError(t, err)
			assert.Equal(t, []byte("test message"), body)

			// Write the response
			w.WriteHeader(http.StatusOK)
			_, err = w.Write([]byte("merkle-root"))
			assert.NoError(t, err)
		}))
		defer server.Close()

		// Create a new HTTPClient
		client := NewHTTPClient(server.URL)

		// Call the SubmitMessage method
		merkleRoot, err := client.SubmitMessage(context.Background(), []byte("test message"))

		// Assert the results
		assert.NoError(t, err)
		assert.Equal(t, "merkle-root", merkleRoot)
	})

	t.Run("server error", func(t *testing.T) {
		// Create a mock server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		// Create a new HTTPClient
		client := NewHTTPClient(server.URL)

		// Call the SubmitMessage method
		_, err := client.SubmitMessage(context.Background(), []byte("test message"))

		// Assert the results
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "received non-200 status code: 500")
	})

	t.Run("network error", func(t *testing.T) {
		// Create a new HTTPClient with an invalid URL
		client := NewHTTPClient("http://localhost:9999")

		// Call the SubmitMessage method
		_, err := client.SubmitMessage(context.Background(), []byte("test message"))

		// Assert the results
		assert.Error(t, err)
	})
}
