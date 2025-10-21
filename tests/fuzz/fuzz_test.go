package fuzz

import (
	"context"
	"log"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fedi-e2ee/pkd-server-go/internal/api"
	"github.com/fedi-e2ee/pkd-server-go/internal/config"
	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/fedi-e2ee/pkd-server-go/internal/tlog"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/mock"

	"github.com/DATA-DOG/go-sqlmock"
)

// MockTransactionalRepository is a mock implementation of the domain.TransactionalRepository interface.
type MockTransactionalRepository struct {
	mock.Mock
}

func (m *MockTransactionalRepository) Commit() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockTransactionalRepository) Rollback() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockTransactionalRepository) GetOrCreateActor(ctx context.Context, actorID string) (*domain.Actor, error) {
	args := m.Called(ctx, actorID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Actor), args.Error(1)
}

func (m *MockTransactionalRepository) FindActorByActorID(ctx context.Context, actorID string) (*domain.Actor, error) {
	args := m.Called(ctx, actorID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Actor), args.Error(1)
}
func (m *MockTransactionalRepository) ActorExists(ctx context.Context, actorID string) (bool, error) {
	args := m.Called(ctx, actorID)
	return args.Bool(0), args.Error(1)
}
func (m *MockTransactionalRepository) UpdateActorID(ctx context.Context, oldActorID, newActorID string) (int64, error) {
	args := m.Called(ctx, oldActorID, newActorID)
	return args.Get(0).(int64), args.Error(1)
}
func (m *MockTransactionalRepository) InsertPublicKey(ctx context.Context, key *domain.PublicKey) (*domain.PublicKey, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.PublicKey), args.Error(1)
}
func (m *MockTransactionalRepository) FindKeyToRevoke(ctx context.Context, actorID, publicKey string) (*domain.PublicKey, error) {
	args := m.Called(ctx, actorID, publicKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.PublicKey), args.Error(1)
}
func (m *MockTransactionalRepository) RevokeKey(ctx context.Context, keyID int64, revokeRoot string) error {
	args := m.Called(ctx, keyID, revokeRoot)
	return args.Error(0)
}
func (m *MockTransactionalRepository) GetMessageHashesForActor(ctx context.Context, actorID int64) ([]string, error) {
	args := m.Called(ctx, actorID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}
func (m *MockTransactionalRepository) RevokeAllKeysForActor(ctx context.Context, actorID int64, merkleRoot string) error {
	args := m.Called(ctx, actorID, merkleRoot)
	return args.Error(0)
}
func (m *MockTransactionalRepository) InsertAuxData(ctx context.Context, aux *domain.AuxiliaryData) (*domain.AuxiliaryData, error) {
	args := m.Called(ctx, aux)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.AuxiliaryData), args.Error(1)
}
func (m *MockTransactionalRepository) RevokeAuxData(ctx context.Context, actorID, auxID, revokeRoot string) (int64, error) {
	args := m.Called(ctx, actorID, auxID, revokeRoot)
	return args.Get(0).(int64), args.Error(1)
}
func (m *MockTransactionalRepository) StoreSymmetricKeys(ctx context.Context, messageHash string, keys map[string][]byte) error {
	args := m.Called(ctx, messageHash, keys)
	return args.Error(0)
}
func (m *MockTransactionalRepository) DeleteSymmetricKeysByHashes(ctx context.Context, hashes []string) error {
	args := m.Called(ctx, hashes)
	return args.Error(0)
}

// MockRepository is a mock implementation of the db.Repository interface for fuzzing.
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) DB() *sqlx.DB {
	return nil
}

func (m *MockRepository) BeginTx(ctx context.Context) (domain.TransactionalRepository, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(domain.TransactionalRepository), args.Error(1)
}

func (m *MockRepository) FindActorByActorID(ctx context.Context, actorID string) (*domain.Actor, error) {
	args := m.Called(ctx, actorID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Actor), args.Error(1)
}

func (m *MockRepository) IsFireproof(ctx context.Context, actorID string) (bool, error) {
	args := m.Called(ctx, actorID)
	return args.Bool(0), args.Error(1)
}

func (m *MockRepository) SetFireproof(ctx context.Context, actorID string, isFireproof bool) error {
	args := m.Called(ctx, actorID, isFireproof)
	return args.Error(0)
}

func (m *MockRepository) ListKeysForActor(ctx context.Context, actorID string) ([]*domain.PublicKey, error) {
	args := m.Called(ctx, actorID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.PublicKey), args.Error(1)
}

func (m *MockRepository) FindKeyByKeyID(ctx context.Context, keyID string) (*domain.PublicKey, error) {
	args := m.Called(ctx, keyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.PublicKey), args.Error(1)
}

func (m *MockRepository) ListAuxDataForActor(ctx context.Context, actorID string) ([]*domain.AuxiliaryData, error) {
	args := m.Called(ctx, actorID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.AuxiliaryData), args.Error(1)
}

func (m *MockRepository) FindAuxDataByAuxID(ctx context.Context, auxID string) (*domain.AuxiliaryData, error) {
	args := m.Called(ctx, auxID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.AuxiliaryData), args.Error(1)
}

func (m *MockRepository) FindSymmetricKeysByMessageHash(ctx context.Context, messageHash string) ([]*domain.SymmetricKey, error) {
	args := m.Called(ctx, messageHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.SymmetricKey), args.Error(1)
}

func (m *MockRepository) StoreMessage(ctx context.Context, hash string, rawMessage []byte, decryptedMessage *protocol.ProtocolMessage) error {
	args := m.Called(ctx, hash, rawMessage, decryptedMessage)
	return args.Error(0)
}

func (m *MockRepository) GetLatestMerkleRoot(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

func (m *MockRepository) StoreTOTPSecret(ctx context.Context, instance string, encryptedSecret []byte) error {
	args := m.Called(ctx, instance, encryptedSecret)
	return args.Error(0)
}

func (m *MockRepository) GetTOTPSecret(ctx context.Context, instance string) ([]byte, error) {
	args := m.Called(ctx, instance)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockRepository) DeleteTOTPSecret(ctx context.Context, instance string) error {
	args := m.Called(ctx, instance)
	return args.Error(0)
}

func (m *MockRepository) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockRepository) AddTlogEntry(ctx context.Context, merkleRoot []byte, signedMessage []byte, publicKeyHash []byte) error {
	args := m.Called(ctx, merkleRoot, signedMessage, publicKeyHash)
	return args.Error(0)
}

func (m *MockRepository) GetAllTlogEntries(ctx context.Context) ([]*domain.TlogEntry, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.TlogEntry), args.Error(1)
}

func (m *MockRepository) Close() error {
	args := m.Called()
	return args.Error(0)
}

func FuzzHTTPHandlers(f *testing.F) {
	// Setup a minimal test instance with a mock repository.
	mockRepo := new(MockRepository)
	mockTx := new(MockTransactionalRepository)
	service := domain.NewPKDService(mockRepo, nil)
	tlogClient := &tlog.MockClient{}
	logger := log.New(os.Stdout, "FUZZ_TEST ", log.LstdFlags)

	// Create a temporary key file for the test run.
	keyFile, err := os.CreateTemp(f.TempDir(), "test.key")
	if err != nil {
		f.Fatalf("failed to create temp key file: %v", err)
	}
	_ = keyFile.Close()

	cfg := &config.Config{
		Server: config.Server{
			KeyFile: config.KeyFile{
				Path:            keyFile.Name(),
				Password:        "test-password",
				Argon2idTime:    1,
				Argon2idMemory:  1024,
				Argon2idThreads: 1,
			},
		},
	}

	db, _, err := sqlmock.New()
	if err != nil {
		f.Fatalf("failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()
	sqlxDB := sqlx.NewDb(db, "sqlmock")

	runtimeState := &api.RuntimeState{
		Repo:           mockRepo,
		Service:        service,
		TlogClient:     tlogClient,
		Logger:         logger,
		HPKEPublicKey:  nil,
		HPKEPrivateKey: nil,
		Config:         cfg,
		DB:             sqlxDB,
	}
	router := api.NewRouter(runtimeState)

	// Add seed corpus.
	f.Add("https://social.example/users/alice")
	f.Add("!@#$%^&*()")
	f.Add("")
	f.Add("user-with-very-long-name-that-might-cause-issues-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

	f.Fuzz(func(t *testing.T, actorID string) {
		// Mock the repository calls.
		mockRepo.On("FindActorByActorID", mock.Anything, mock.Anything).Return(&domain.Actor{
			ID:        1,
			ActorID:   "https://social.example/users/mock",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}, nil).Maybe()
		mockRepo.On("BeginTx", mock.Anything).Return(mockTx, nil).Maybe()
		mockTx.On("Commit").Return(nil).Maybe()
		mockTx.On("Rollback").Return(nil).Maybe()

		// Create a request with the fuzzed actorID.
		// We use url.PathEscape to ensure the path is valid.
		req := httptest.NewRequest("GET", "/api/actor/"+url.PathEscape(actorID), nil)
		rec := httptest.NewRecorder()

		// Serve the request to the router.
		router.ServeHTTP(rec, req)

		// The fuzzer will automatically detect panics and crashes.
		// No explicit assertions are needed here. We just want to ensure
		// that the handler can process any input without crashing.
	})
}

func FuzzProtocolHandler(f *testing.F) {
	// Setup a minimal test instance with a mock repository.
	mockRepo := new(MockRepository)
	mockTx := new(MockTransactionalRepository)
	tlogClient := &tlog.MockClient{}
	logger := log.New(os.Stdout, "FUZZ_TEST ", log.LstdFlags)

	// Create a temporary key file for the test run.
	keyFile, err := os.CreateTemp(f.TempDir(), "test.key")
	if err != nil {
		f.Fatalf("failed to create temp key file: %v", err)
	}
	_ = keyFile.Close()

	cfg := &config.Config{
		Server: config.Server{
			KeyFile: config.KeyFile{
				Path:            keyFile.Name(),
				Password:        "test-password",
				Argon2idTime:    1,
				Argon2idMemory:  1024,
				Argon2idThreads: 1,
			},
		},
	}

	// Add seed corpus with various JSON structures.
	f.Add(`{"action":"AddKey","message":{}}`)
	f.Add(`{"action":"AddKey","message":{"actor":"test","public_key":"test"}}`)
	f.Add(`{"action":"UnknownAction","message":{}}`)
	f.Add(`{`)
	f.Add(`null`)

	mockService := domain.NewPKDService(mockRepo, nil)

	db, _, err := sqlmock.New()
	if err != nil {
		f.Fatalf("failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()
	sqlxDB := sqlx.NewDb(db, "sqlmock")

	runtimeState := &api.RuntimeState{
		Repo:           mockRepo,
		Service:        mockService,
		TlogClient:     tlogClient,
		Logger:         logger,
		HPKEPublicKey:  nil,
		HPKEPrivateKey: nil,
		Config:         cfg,
		DB:             sqlxDB,
	}
	router := api.NewRouter(runtimeState)

	f.Fuzz(func(t *testing.T, body string) {
		// Mock all the repository and service calls that might be triggered.
		mockRepo.On("ListKeysForActor", mock.Anything, mock.Anything).Return([]*domain.PublicKey{}, nil).Maybe()
		mockRepo.On("BeginTx", mock.Anything).Return(mockTx, nil).Maybe()
		mockTx.On("Commit").Return(nil).Maybe()
		mockTx.On("Rollback").Return(nil).Maybe()
		mockTx.On("GetOrCreateActor", mock.Anything, mock.Anything).Return(&domain.Actor{ID: 1}, nil).Maybe()
		mockTx.On("InsertPublicKey", mock.Anything, mock.Anything).Return(&domain.PublicKey{KeyID: "new-key-id"}, nil).Maybe()
		mockTx.On("StoreSymmetricKeys", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

		tlogClient.On("SubmitMessage", mock.Anything, mock.Anything).Return("mock-merkle-root", nil).Maybe()

		req := httptest.NewRequest("POST", "/protocol", strings.NewReader(body))
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)
	})
}

func FuzzGetKeyInfo(f *testing.F) {
	// Setup a minimal test instance with a mock repository.
	mockRepo := new(MockRepository)
	service := domain.NewPKDService(mockRepo, nil)
	tlogClient := &tlog.MockClient{}
	logger := log.New(os.Stdout, "FUZZ_TEST ", log.LstdFlags)

	keyFile, err := os.CreateTemp(f.TempDir(), "test.key")
	if err != nil {
		f.Fatalf("failed to create temp key file: %v", err)
	}
	_ = keyFile.Close()

	cfg := &config.Config{
		Server: config.Server{
			KeyFile: config.KeyFile{
				Path:            keyFile.Name(),
				Password:        "test-password",
				Argon2idTime:    1,
				Argon2idMemory:  1024,
				Argon2idThreads: 1,
			},
		},
	}

	db, _, err := sqlmock.New()
	if err != nil {
		f.Fatalf("failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()
	sqlxDB := sqlx.NewDb(db, "sqlmock")

	runtimeState := &api.RuntimeState{
		Repo:           mockRepo,
		Service:        service,
		TlogClient:     tlogClient,
		Logger:         logger,
		HPKEPublicKey:  nil,
		HPKEPrivateKey: nil,
		Config:         cfg,
		DB:             sqlxDB,
	}
	router := api.NewRouter(runtimeState)

	// Add seed corpus.
	f.Add("https://social.example/users/alice", "key1")
	f.Add("!@#$%^&*()", "!@#$%^&*()")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, actorID, keyID string) {
		// Mock the repository call.
		mockRepo.On("FindKeyByKeyID", mock.Anything, mock.Anything).Return(&domain.PublicKey{
			ID: 1, ActorID: 1, KeyID: "key1", PublicKey: "pubkey1",
		}, nil).Maybe()

		req := httptest.NewRequest("GET", "/api/actor/"+url.PathEscape(actorID)+"/key/"+url.PathEscape(keyID), nil)
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)
	})
}

func FuzzGetActorKeys(f *testing.F) {
	// Setup a minimal test instance with a mock repository.
	mockRepo := new(MockRepository)
	service := domain.NewPKDService(mockRepo, nil)
	tlogClient := &tlog.MockClient{}
	logger := log.New(os.Stdout, "FUZZ_TEST ", log.LstdFlags)

	keyFile, err := os.CreateTemp(f.TempDir(), "test.key")
	if err != nil {
		f.Fatalf("failed to create temp key file: %v", err)
	}
	_ = keyFile.Close()

	cfg := &config.Config{
		Server: config.Server{
			KeyFile: config.KeyFile{
				Path:            keyFile.Name(),
				Password:        "test-password",
				Argon2idTime:    1,
				Argon2idMemory:  1024,
				Argon2idThreads: 1,
			},
		},
	}

	db, _, err := sqlmock.New()
	if err != nil {
		f.Fatalf("failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()
	sqlxDB := sqlx.NewDb(db, "sqlmock")

	runtimeState := &api.RuntimeState{
		Repo:           mockRepo,
		Service:        service,
		TlogClient:     tlogClient,
		Logger:         logger,
		HPKEPublicKey:  nil,
		HPKEPrivateKey: nil,
		Config:         cfg,
		DB:             sqlxDB,
	}
	router := api.NewRouter(runtimeState)

	// Add seed corpus.
	f.Add("https://social.example/users/alice")
	f.Add("!@#$%^&*()")
	f.Add("")

	f.Fuzz(func(t *testing.T, actorID string) {
		// Mock the repository call.
		mockRepo.On("ListKeysForActor", mock.Anything, mock.Anything).Return([]*domain.PublicKey{
			{ID: 1, ActorID: 1, KeyID: "key1", PublicKey: "pubkey1"},
		}, nil).Maybe()

		req := httptest.NewRequest("GET", "/api/actor/"+url.PathEscape(actorID)+"/keys", nil)
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)
	})
}
