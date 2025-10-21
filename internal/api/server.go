package api

import (
	"log"
	"net/http"

	"github.com/fedi-e2ee/pkd-server-go/internal/auth"
	"github.com/fedi-e2ee/pkd-server-go/internal/config"
	"github.com/fedi-e2ee/pkd-server-go/internal/db"
	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/fedi-e2ee/pkd-server-go/internal/tlog"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jmoiron/sqlx"
)

// RuntimeState holds the dependencies for the NewRouter function.
type RuntimeState struct {
	Repo           db.Repository
	Service        domain.Service
	TlogClient     tlog.Client
	Logger         *log.Logger
	HPKEPublicKey  interface{}
	HPKEPrivateKey interface{}
	Config         *config.Config
	DB             *sqlx.DB
}

// Server holds the dependencies for the API handlers, including the database repository,
// domain service, Tlog client, logger, and server-specific configurations. It also
// contains a map of protocol action handlers for routing protocol messages.
type Server struct {
	repo           db.Repository
	service        domain.Service
	tlog           tlog.Client
	logger         *log.Logger
	hpkePrivateKey interface{}
	hpkePublicKey  interface{}
	config         *config.Config
	actionHandlers map[string]protocolActionHandler
	tokenService   auth.TokenService
	db             *sqlx.DB
}

// NewRouter creates a new chi router and sets up all the API routes and handlers.
// It initializes the Server struct with all its dependencies and registers the
// protocol message handlers and REST API endpoints.
func NewRouter(rs *RuntimeState) http.Handler {
	// Create the key manager and token service.
	keyManager, err := auth.NewFileKeyManager(
		rs.Config.Server.KeyFile.Path,
		[]byte(rs.Config.Server.KeyFile.Password),
		rs.Config.Server.KeyFile.Argon2idTime,
		rs.Config.Server.KeyFile.Argon2idMemory,
		rs.Config.Server.KeyFile.Argon2idThreads,
	)
	if err != nil {
		rs.Logger.Fatalf("Failed to create key manager: %v", err)
	}
	tokenService := auth.NewPasetoTokenService(keyManager, rs.Config, rs.DB)

	s := &Server{
		repo:           rs.Repo,
		service:        rs.Service,
		tlog:           rs.TlogClient,
		logger:         rs.Logger,
		hpkePublicKey:  rs.HPKEPublicKey,
		hpkePrivateKey: rs.HPKEPrivateKey,
		config:         rs.Config,
		tokenService:   tokenService,
		db:             rs.DB,
	}

	s.actionHandlers = map[string]protocolActionHandler{
		"AddKey":        s.processAddKeyAction,
		"RevokeKey":     s.processRevokeKeyAction,
		"MoveIdentity":  s.processMoveIdentityAction,
		"BurnDown":      s.processBurnDownAction,
		"Fireproof":     s.processFireproofAction,
		"UndoFireproof": s.processUndoFireproofAction,
		"AddAuxData":    s.processAddAuxDataAction,
		"RevokeAuxData": s.processRevokeAuxDataAction,
		"Checkpoint":    s.processCheckpointAction,
		"Query":         s.processQueryAction,
	}

	r := chi.NewRouter()

	// A good base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Set a reasonable request size limit to prevent trivial DoS attacks.
	r.Use(middleware.RequestSize(1 << 20)) // 1 MB

	// REST API routes from Specification.md
	r.Route("/api", func(r chi.Router) {
		// Actor routes
		r.Get("/actor/{actorID}", s.handleGetActorInfo)
		r.Get("/actor/{actorID}/keys", s.handleGetActorKeys)
		r.Get("/actor/{actorID}/key/{keyID}", s.handleGetKeyInfo)
		r.Get("/actor/{actorID}/auxiliary", s.handleGetActorAuxiliary)
		r.Get("/actor/{actorID}/auxiliary/{auxDataID}", s.handleGetAuxiliaryDataInfo)

		// History routes
		r.Get("/history", s.handleGetHistory)
		r.Get("/history/since/{lastHash}", s.handleGetHistorySince)
		r.Get("/history/view/{hash}", s.handleGetHistoryView)

		// Server info
		r.Get("/extensions", s.handleGetExtensions)
		r.Get("/replicas", s.handleGetReplicas)
		r.Get("/server-public-key", s.handleGetServerPublicKey)

		// Actions
		r.Post("/revoke", s.handleRevoke)

		// TOTP
		r.Post("/totp/enroll", s.handleTotpEnroll)
		r.Post("/totp/disenroll", s.handleTotpDisenroll)
		r.Post("/totp/rotate", s.handleTotpRotate)

		// Replicas
		r.Get("/replica/{replicaID}/*", s.handleReplica)
	})

	// Protocol message handler endpoint
	r.Post("/protocol", s.handleProtocolMessage)

	// Admin routes
	r.Route("/admin", func(r chi.Router) {
		r.Use(s.authMiddleware)
		r.Post("/checkpoint", s.handleTriggerCheckpoint)
		r.Post("/crypto-shred", s.handleCryptoShred)
	})

	// Well-known endpoint for server discovery
	r.Get("/.well-known/pkd", s.handleWellKnownPKD)

	return r
}

// handleWellKnownPKD serves the /.well-known/pkd endpoint, which provides
// server configuration details to clients.
// See: https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#well-known-endpoint
func (s *Server) handleWellKnownPKD(w http.ResponseWriter, r *http.Request) {
	// Construct the list of peer URLs from the config.
	var peers []string
	for peerURL := range s.config.Peers {
		peers = append(peers, peerURL)
	}

	// The response should include the server's public key and a list of its peers.
	response := map[string]interface{}{
		"server-public-key": s.hpkePublicKey,
		"peers":             peers,
	}

	s.respondWithJSON(w, http.StatusOK, response)
}

// handleGetActorInfo handles fetching information about a specific actor.
func (s *Server) handleGetActorInfo(w http.ResponseWriter, r *http.Request) {
	actorID, err := url.PathUnescape(chi.URLParam(r, "actorID"))
	if err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid actor ID")
		return
	}
	actor, err := s.repo.FindActorByActorID(r.Context(), actorID)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve actor information")
		return
	}
	if actor == nil {
		s.respondWithError(w, http.StatusNotFound, "Actor not found")
		return
	}
	s.respondWithJSON(w, http.StatusOK, actor)
}

// handleGetActorKeys handles fetching all public keys for a specific actor.
func (s *Server) handleGetActorKeys(w http.ResponseWriter, r *http.Request) {
	actorID := chi.URLParam(r, "actorID")
	keys, err := s.repo.ListKeysForActor(r.Context(), actorID)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve actor keys")
		return
	}
	s.respondWithJSON(w, http.StatusOK, keys)
}

// handleGetKeyInfo handles fetching information about a specific public key.
func (s *Server) handleGetKeyInfo(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "keyID")
	key, err := s.repo.FindKeyByKeyID(r.Context(), keyID)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve key information")
		return
	}
	if key == nil {
		s.respondWithError(w, http.StatusNotFound, "Key not found")
		return
	}
	s.respondWithJSON(w, http.StatusOK, key)
}

// handleGetActorAuxiliary handles fetching all auxiliary data for a specific actor.
func (s *Server) handleGetActorAuxiliary(w http.ResponseWriter, r *http.Request) {
	actorID := chi.URLParam(r, "actorID")
	auxData, err := s.repo.ListAuxDataForActor(r.Context(), actorID)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve auxiliary data")
		return
	}
	s.respondWithJSON(w, http.StatusOK, auxData)
}

// handleGetAuxiliaryDataInfo handles fetching a specific piece of auxiliary data.
func (s *Server) handleGetAuxiliaryDataInfo(w http.ResponseWriter, r *http.Request) {
	auxDataID := chi.URLParam(r, "auxDataID")
	auxData, err := s.repo.FindAuxDataByAuxID(r.Context(), auxDataID)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve auxiliary data information")
		return
	}
	if auxData == nil {
		s.respondWithError(w, http.StatusNotFound, "Auxiliary data not found")
		return
	}
	s.respondWithJSON(w, http.StatusOK, auxData)
}

// handleGetServerPublicKey handles returning the server's public key.
func (s *Server) handleGetServerPublicKey(w http.ResponseWriter, r *http.Request) {
	s.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"public_key": s.hpkePublicKey,
	})
}

// handleGetExtensions returns a list of supported extensions.
func (s *Server) handleGetExtensions(w http.ResponseWriter, r *http.Request) {
	extensions := []string{
		protocol.ExtensionURNOLM,
	}
	s.respondWithJSON(w, http.StatusOK, extensions)
}

// handleGetReplicas returns a list of peer directories.
func (s *Server) handleGetReplicas(w http.ResponseWriter, r *http.Request) {
	var replicas []string
	for replicaURL := range s.config.Peers {
		replicas = append(replicas, replicaURL)
	}
	s.respondWithJSON(w, http.StatusOK, replicas)
}

// --- Placeholder Handlers (to be implemented) ---

func (s *Server) handleGetHistory(w http.ResponseWriter, r *http.Request)      {}
func (s *Server) handleGetHistorySince(w http.ResponseWriter, r *http.Request) {}
func (s *Server) handleGetHistoryView(w http.ResponseWriter, r *http.Request)  {}
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request)          {}
func (s *Server) handleTotpEnroll(w http.ResponseWriter, r *http.Request)      {}
func (s *Server) handleTotpDisenroll(w http.ResponseWriter, r *http.Request)   {}
func (s *Server) handleTotpRotate(w http.ResponseWriter, r *http.Request)      {}
func (s *Server) handleReplica(w http.ResponseWriter, r *http.Request)         {}
