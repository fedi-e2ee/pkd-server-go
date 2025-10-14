package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fedi-e2ee/pkd-server-go/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestServer_handleWellKnownPKD(t *testing.T) {
	t.Run("returns server config", func(t *testing.T) {
		// setup
		server := &Server{
			config: &config.Config{
				Peers: map[string]config.Peer{
					"peer-1": {
						PublicKey: "public-key-1",
					},
					"peer-2": {
						PublicKey: "public-key-2",
					},
				},
			},
			hpkePublicKey: "server-public-key",
		}
		req := httptest.NewRequest(http.MethodGet, "/.well-known/pkd", nil)
		res := httptest.NewRecorder()

		// exercise
		server.handleWellKnownPKD(res, req)

		// assert
		assert.Equal(t, http.StatusOK, res.Code)
		var response map[string]interface{}
		err := json.Unmarshal(res.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "server-public-key", response["server-public-key"])
		assert.ElementsMatch(t, []string{"peer-1", "peer-2"}, response["peers"])
	})
}
