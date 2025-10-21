package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fedi-e2ee/pkd-server-go/internal/api"
	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	"github.com/fedi-e2ee/pkd-server-go/internal/testutil"
	"net/url"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleGetActorInfo(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	if err != nil {
		t.Fatalf("failed to create test instance: %v", err)
	}
	defer ti.Teardown()

	mockRepo := new(MockRepository)
	ti.Service = domain.NewPKDService(mockRepo, nil) // Replace the real repo with the mock
	runtimeState := &api.RuntimeState{
		Repo:           mockRepo,
		Service:        ti.Service,
		TlogClient:     ti.TlogClient,
		Logger:         ti.Logger,
		HPKEPublicKey:  ti.PubKey,
		HPKEPrivateKey: nil,
		Config:         ti.Config,
		DB:             ti.DB,
	}
	ti.Router = api.NewRouter(runtimeState)
	ti.Server = httptest.NewServer(ti.Router)

	// --- Test Case 1: Actor Found ---
	t.Run("Actor Found", func(t *testing.T) {
		actorID := "https://social.example/users/alice"
		expectedActor := &domain.Actor{
			ID:        1,
			ActorID:   actorID,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		mockRepo.On("FindActorByActorID", mock.Anything, actorID).Return(expectedActor, nil).Once()

		req := httptest.NewRequest("GET", "/api/actor/"+url.PathEscape(actorID), nil)
		rec := httptest.NewRecorder()
		ti.Router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		var actualActor domain.Actor
		err := json.Unmarshal(rec.Body.Bytes(), &actualActor)
		assert.NoError(t, err)
		assert.Equal(t, expectedActor.ActorID, actualActor.ActorID)
	})

	// --- Test Case 2: Actor Not Found ---
	t.Run("Actor Not Found", func(t *testing.T) {
		actorID := "https://social.example/users/bob"
		mockRepo.On("FindActorByActorID", mock.Anything, actorID).Return(nil, nil).Once()

		req := httptest.NewRequest("GET", "/api/actor/"+url.PathEscape(actorID), nil)
		rec := httptest.NewRecorder()
		ti.Router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}
