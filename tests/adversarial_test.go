package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/fedi-e2ee/pkd-server-go/internal/api"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/fedi-e2ee/pkd-server-go/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdversarial_SQLInjection(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti.Teardown()

	maliciousActorID := "' OR 1=1--"
	req := httptest.NewRequest("GET", "/api/actor/"+url.PathEscape(maliciousActorID), nil)
	resp := httptest.NewRecorder()
	ti.Router.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusNotFound, resp.Code, "Expected status not found for SQL injection in actorID")
}

func TestAdversarial_PathTraversal(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti.Teardown()

	maliciousPath := "../../../../etc/passwd"
	req := httptest.NewRequest("GET", "/api/actor/"+url.PathEscape(maliciousPath), nil)
	resp := httptest.NewRecorder()
	ti.Router.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusNotFound, resp.Code, "Expected status not found for path traversal in actorID")
}

func TestAdversarial_DenialOfService(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti.Teardown()

	largeString := strings.Repeat("a", 2*1024*1024)
	protoMsg := protocol.ProtocolMessage{
		PKDContext: protocol.PKDContextV1,
		Action:     "AddKey",
		Message:    json.RawMessage(`{"actor":"` + largeString + `"}`),
	}
	largePayload, err := json.Marshal(protoMsg)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/protocol", bytes.NewReader(largePayload))
	resp := httptest.NewRecorder()
	ti.Router.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.Code, "Expected status request entity too large for large payload")
}

func TestAdversarial_ProtocolHandler(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti.Teardown()

	req := httptest.NewRequest("POST", "/protocol", bytes.NewReader([]byte("{malformed")))
	resp := httptest.NewRecorder()
	ti.Router.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusBadRequest, resp.Code, "Expected status bad request for malformed JSON")

	jsonBody := `{"!pkd-context": "https://github.com/fedi-e2ee/public-key-directory/v1", "action": "InvalidAction", "message": "{}"}`
	req = httptest.NewRequest("POST", "/protocol", bytes.NewReader([]byte(jsonBody)))
	resp = httptest.NewRecorder()
	ti.Router.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusBadRequest, resp.Code, "Expected status bad request for invalid action")
}

func TestAdversarial_AdminEndpoints(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti.Teardown()

	req := httptest.NewRequest("POST", "/admin/checkpoint", nil)
	resp := httptest.NewRecorder()
	ti.Router.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusUnauthorized, resp.Code, "Expected status unauthorized for unauthorized access")

	accessToken, _, err := ti.TokenService.NewPair()
	require.NoError(t, err)

	largeString := strings.Repeat("a", 2*1024*1024)
	checkpointReq := api.TriggerCheckpointRequest{
		ToDirectory: largeString,
	}
	largePayload, err := json.Marshal(checkpointReq)
	require.NoError(t, err)

	req = httptest.NewRequest("POST", "/admin/checkpoint", bytes.NewReader(largePayload))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp = httptest.NewRecorder()
	ti.Router.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.Code, "Expected status request entity too large for large payload")
}
