package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fedi-e2ee/pkd-server-go/internal/crypto"
	"github.com/fedi-e2ee/pkd-server-go/internal/config"
	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/fedi-e2ee/pkd-server-go/internal/sigsum"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockDBRepository is a mock of the db.Repository interface
type MockDBRepository struct {
	mock.Mock
}

func (m *MockDBRepository) DB() *sqlx.DB {
	return nil
}

func (m *MockDBRepository) BeginTx(ctx context.Context) (domain.TransactionalRepository, error) {
	args := m.Called(ctx)
	return args.Get(0).(domain.TransactionalRepository), args.Error(1)
}
func (m *MockDBRepository) FindActorByActorID(ctx context.Context, actorID string) (*domain.Actor, error) {
	args := m.Called(ctx, actorID)
	return args.Get(0).(*domain.Actor), args.Error(1)
}
func (m *MockDBRepository) IsFireproof(ctx context.Context, actorID string) (bool, error) {
	args := m.Called(ctx, actorID)
	return args.Bool(0), args.Error(1)
}
func (m *MockDBRepository) SetFireproof(ctx context.Context, actorID string, isFireproof bool) error {
	args := m.Called(ctx, actorID, isFireproof)
	return args.Error(0)
}
func (m *MockDBRepository) ListKeysForActor(ctx context.Context, actorID string) ([]*domain.PublicKey, error) {
	args := m.Called(ctx, actorID)
	return args.Get(0).([]*domain.PublicKey), args.Error(1)
}
func (m *MockDBRepository) FindKeyByKeyID(ctx context.Context, keyID string) (*domain.PublicKey, error) {
	args := m.Called(ctx, keyID)
	return args.Get(0).(*domain.PublicKey), args.Error(1)
}
func (m *MockDBRepository) ListAuxDataForActor(ctx context.Context, actorID string) ([]*domain.AuxiliaryData, error) {
	args := m.Called(ctx, actorID)
	return args.Get(0).([]*domain.AuxiliaryData), args.Error(1)
}
func (m *MockDBRepository) FindAuxDataByAuxID(ctx context.Context, auxID string) (*domain.AuxiliaryData, error) {
	args := m.Called(ctx, auxID)
	return args.Get(0).(*domain.AuxiliaryData), args.Error(1)
}
func (m *MockDBRepository) FindSymmetricKeysByMessageHash(ctx context.Context, messageHash string) ([]*domain.SymmetricKey, error) {
	args := m.Called(ctx, messageHash)
	return args.Get(0).([]*domain.SymmetricKey), args.Error(1)
}
func (m *MockDBRepository) StoreMessage(ctx context.Context, hash string, rawMessage []byte, decryptedMessage *protocol.ProtocolMessage) error {
	args := m.Called(ctx, hash, rawMessage, decryptedMessage)
	return args.Error(0)
}
func (m *MockDBRepository) GetLatestMerkleRoot(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}
func (m *MockDBRepository) StoreTOTPSecret(ctx context.Context, instance string, encryptedSecret []byte) error {
	args := m.Called(ctx, instance, encryptedSecret)
	return args.Error(0)
}
func (m *MockDBRepository) GetTOTPSecret(ctx context.Context, instance string) ([]byte, error) {
	args := m.Called(ctx, instance)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}
func (m *MockDBRepository) DeleteTOTPSecret(ctx context.Context, instance string) error {
	args := m.Called(ctx, instance)
	return args.Error(0)
}
func (m *MockDBRepository) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}
func (m *MockDBRepository) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockService is a mock of the domain.Service interface
type MockService struct {
	mock.Mock
}

func (m *MockService) CryptoShred(ctx context.Context, actorID string) error {
	args := m.Called(ctx, actorID)
	return args.Error(0)
}
func (m *MockService) ProcessAddKey(ctx context.Context, msg *protocol.AddKeyMessage, merkleRoot string, symKeys map[string][]byte) (*domain.PublicKey, error) {
	args := m.Called(ctx, msg, merkleRoot, symKeys)
	return args.Get(0).(*domain.PublicKey), args.Error(1)
}
func (m *MockService) ProcessRevokeKey(ctx context.Context, msg *protocol.RevokeKeyMessage, merkleRoot string, symKeys map[string][]byte) error {
	args := m.Called(ctx, msg, merkleRoot, symKeys)
	return args.Error(0)
}
func (m *MockService) ProcessMoveIdentity(ctx context.Context, msg *protocol.MoveIdentityMessage, merkleRoot string) error {
	args := m.Called(ctx, msg, merkleRoot)
	return args.Error(0)
}
func (m *MockService) ProcessBurnDown(ctx context.Context, actorID string, merkleRoot string) error {
	args := m.Called(ctx, actorID, merkleRoot)
	return args.Error(0)
}
func (m *MockService) ProcessAddAuxData(ctx context.Context, msg *protocol.AddAuxDataMessage, merkleRoot string) (*domain.AuxiliaryData, error) {
	args := m.Called(ctx, msg, merkleRoot)
	return args.Get(0).(*domain.AuxiliaryData), args.Error(1)
}
func (m *MockService) ProcessRevokeAuxData(ctx context.Context, msg *protocol.RevokeAuxDataMessage, merkleRoot string) error {
	args := m.Called(ctx, msg, merkleRoot)
	return args.Error(0)
}

func TestProcessAddKeyAction_FirstKey(t *testing.T) {
	// Create mock service and sigsum client
	mockService := new(MockService)
	mockSigsum := new(sigsum.MockClient)
	mockRepo := new(MockDBRepository)

	// Create a new server with the mock dependencies
	server := &Server{
		service: mockService,
		sigsum:  mockSigsum,
		repo:    mockRepo,
	}

	// Generate a new key pair for signing
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	pubKeyStr := crypto.EncodePublicKey(pub)

	// Create a sample AddKeyMessage
	addKeyMsg := protocol.AddKeyMessage{
		Actor:     "test-actor",
		Time:      "2024-01-01T00:00:00Z",
		PublicKey: pubKeyStr,
	}
	addKeyMsgJSON, err := json.Marshal(addKeyMsg)
	assert.NoError(t, err)

	// Create the canonical message form for signing
	signedMsg := protocol.SignedMessage{
		PKDContext:       protocol.PKDContextV1,
		Action:           "AddKey",
		Message:          addKeyMsgJSON,
		RecentMerkleRoot: "test-merkle-root",
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	assert.NoError(t, err)

	// Sign the message
	signature := ed25519.Sign(priv, signedMsgBytes)
	signatureStr := base64.RawURLEncoding.EncodeToString(signature)

	// Create the full protocol message
	protocolMsg := protocol.ProtocolMessage{
		PKDContext:       protocol.PKDContextV1,
		Action:           "AddKey",
		Message:          addKeyMsgJSON,
		RecentMerkleRoot: "test-merkle-root",
		Signature:        signatureStr,
		SymmetricKeys:    map[string]string{"attr1": "Zm9v"}, // "foo" in base64
	}

	// Set up mock expectations
	mockRepo.On("ListKeysForActor", mock.Anything, "test-actor").Return([]*domain.PublicKey{}, nil).Once()
	mockSigsum.On("SubmitMessage", mock.Anything, mock.Anything).Return("test-merkle-root", nil).Once()
	mockService.On("ProcessAddKey", mock.Anything, &addKeyMsg, "test-merkle-root", map[string][]byte{"attr1": []byte("foo")}).Return(&domain.PublicKey{KeyID: "new-key-id", MerkleRoot: "test-merkle-root"}, nil).Once()

	// Create a new HTTP request
	req, err := http.NewRequest("POST", "/protocol", bytes.NewBuffer([]byte{}))
	assert.NoError(t, err)

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the handler
	server.processAddKeyAction(rr, req, &protocolMsg)

	// Check the status code and response body
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, `{"key_id":"new-key-id", "merkle_root":"test-merkle-root"}`, rr.Body.String())

	// Assert that the mock methods were called
	mockRepo.AssertExpectations(t)
	mockService.AssertExpectations(t)
	mockSigsum.AssertExpectations(t)
}

func TestProcessQueryAction(t *testing.T) {
	mockRepo := new(MockDBRepository)
	server := &Server{repo: mockRepo}

	queryMsg := protocol.QueryMessage{Actor: "test-actor"}
	queryMsgJSON, _ := json.Marshal(queryMsg)

	protocolMsg := protocol.ProtocolMessage{
		Action: "Query", Message: queryMsgJSON,
	}

	expectedKeys := []*domain.PublicKey{{KeyID: "key1"}, {KeyID: "key2"}}
	mockRepo.On("ListKeysForActor", mock.Anything, "test-actor").Return(expectedKeys, nil).Once()

	req, _ := http.NewRequest("POST", "/protocol", nil)
	rr := httptest.NewRecorder()
	server.processQueryAction(rr, req, &protocolMsg)

	assert.Equal(t, http.StatusOK, rr.Code)
	var returnedKeys []*domain.PublicKey
	err := json.Unmarshal(rr.Body.Bytes(), &returnedKeys)
	assert.NoError(t, err)
	assert.Equal(t, expectedKeys, returnedKeys)
	mockRepo.AssertExpectations(t)
}

func TestProcessCheckpointAction(t *testing.T) {
	mockRepo := new(MockDBRepository)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyStr := base64.RawURLEncoding.EncodeToString(pub)

	server := &Server{repo: mockRepo, config: &config.Config{
		Peers: map[string]config.Peer{
			"test-directory": {PublicKey: pubKeyStr},
		},
	}}

	checkpointMsg := protocol.CheckpointMessage{FromDirectory: "test-directory"}
	checkpointMsgJSON, _ := json.Marshal(checkpointMsg)

	signedMsg := protocol.SignedMessage{
		PKDContext: protocol.PKDContextV1, Action: "Checkpoint", Message: checkpointMsgJSON,
	}
	signedMsgBytes, _ := json.Marshal(signedMsg)
	signature := ed25519.Sign(priv, signedMsgBytes)
	signatureStr := base64.RawURLEncoding.EncodeToString(signature)

	protocolMsg := protocol.ProtocolMessage{
		PKDContext: protocol.PKDContextV1, Action: "Checkpoint", Message: checkpointMsgJSON, Signature: signatureStr,
	}

	mockRepo.On("StoreMessage", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

	req, _ := http.NewRequest("POST", "/protocol", nil)
	rr := httptest.NewRecorder()
	server.processCheckpointAction(rr, req, &protocolMsg)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockRepo.AssertExpectations(t)
}

func TestProcessFireproofAction(t *testing.T) {
	mockRepo := new(MockDBRepository)
	mockSigsum := new(sigsum.MockClient)
	server := &Server{repo: mockRepo, sigsum: mockSigsum}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	pubKeyStr := crypto.EncodePublicKey(pub)

	fireproofMsg := protocol.FireproofMessage{Actor: "test-actor", Time: "2024-01-01T00:00:00Z"}
	fireproofMsgJSON, _ := json.Marshal(fireproofMsg)

	signedMsg := protocol.SignedMessage{
		PKDContext: protocol.PKDContextV1, Action: "Fireproof", Message: fireproofMsgJSON, RecentMerkleRoot: "test-merkle-root",
	}
	signedMsgBytes, _ := json.Marshal(signedMsg)
	signature := ed25519.Sign(priv, signedMsgBytes)
	signatureStr := base64.RawURLEncoding.EncodeToString(signature)

	protocolMsg := protocol.ProtocolMessage{
		PKDContext: protocol.PKDContextV1, Action: "Fireproof", Message: fireproofMsgJSON, RecentMerkleRoot: "test-merkle-root", Signature: signatureStr,
	}

	mockRepo.On("ListKeysForActor", mock.Anything, "test-actor").Return([]*domain.PublicKey{{PublicKey: pubKeyStr}}, nil).Once()
	mockSigsum.On("SubmitMessage", mock.Anything, mock.Anything).Return("", nil).Once()
	mockRepo.On("SetFireproof", mock.Anything, "test-actor", true).Return(nil).Once()

	req, _ := http.NewRequest("POST", "/protocol", nil)
	rr := httptest.NewRecorder()
	server.processFireproofAction(rr, req, &protocolMsg)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockRepo.AssertExpectations(t)
	mockSigsum.AssertExpectations(t)
}

func TestProcessUndoFireproofAction(t *testing.T) {
	mockRepo := new(MockDBRepository)
	mockSigsum := new(sigsum.MockClient)
	server := &Server{repo: mockRepo, sigsum: mockSigsum}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	pubKeyStr := crypto.EncodePublicKey(pub)

	undoMsg := protocol.UndoFireproofMessage{Actor: "test-actor", Time: "2024-01-01T00:00:00Z"}
	undoMsgJSON, _ := json.Marshal(undoMsg)

	signedMsg := protocol.SignedMessage{
		PKDContext: protocol.PKDContextV1, Action: "UndoFireproof", Message: undoMsgJSON, RecentMerkleRoot: "test-merkle-root",
	}
	signedMsgBytes, _ := json.Marshal(signedMsg)
	signature := ed25519.Sign(priv, signedMsgBytes)
	signatureStr := base64.RawURLEncoding.EncodeToString(signature)

	protocolMsg := protocol.ProtocolMessage{
		PKDContext: protocol.PKDContextV1, Action: "UndoFireproof", Message: undoMsgJSON, RecentMerkleRoot: "test-merkle-root", Signature: signatureStr,
	}

	mockRepo.On("ListKeysForActor", mock.Anything, "test-actor").Return([]*domain.PublicKey{{PublicKey: pubKeyStr}}, nil).Once()
	mockSigsum.On("SubmitMessage", mock.Anything, mock.Anything).Return("", nil).Once()
	mockRepo.On("SetFireproof", mock.Anything, "test-actor", false).Return(nil).Once()

	req, _ := http.NewRequest("POST", "/protocol", nil)
	rr := httptest.NewRecorder()
	server.processUndoFireproofAction(rr, req, &protocolMsg)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockRepo.AssertExpectations(t)
	mockSigsum.AssertExpectations(t)
}

func TestProcessAddAuxDataAction(t *testing.T) {
	mockService := new(MockService)
	mockRepo := new(MockDBRepository)
	mockSigsum := new(sigsum.MockClient)
	server := &Server{service: mockService, repo: mockRepo, sigsum: mockSigsum}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	pubKeyStr := crypto.EncodePublicKey(pub)

	addAuxMsg := protocol.AddAuxDataMessage{Actor: "test-actor", AuxType: "test-type", AuxData: "test-data", Time: "2024-01-01T00:00:00Z"}
	addAuxMsgJSON, _ := json.Marshal(addAuxMsg)

	signedMsg := protocol.SignedMessage{
		PKDContext: protocol.PKDContextV1, Action: "AddAuxData", Message: addAuxMsgJSON, RecentMerkleRoot: "test-merkle-root",
	}
	signedMsgBytes, _ := json.Marshal(signedMsg)
	signature := ed25519.Sign(priv, signedMsgBytes)
	signatureStr := base64.RawURLEncoding.EncodeToString(signature)

	protocolMsg := protocol.ProtocolMessage{
		PKDContext: protocol.PKDContextV1, Action: "AddAuxData", Message: addAuxMsgJSON, RecentMerkleRoot: "test-merkle-root", Signature: signatureStr,
	}

	mockRepo.On("ListKeysForActor", mock.Anything, "test-actor").Return([]*domain.PublicKey{{PublicKey: pubKeyStr}}, nil).Once()
	mockSigsum.On("SubmitMessage", mock.Anything, mock.Anything).Return("test-merkle-root", nil).Once()
	mockService.On("ProcessAddAuxData", mock.Anything, &addAuxMsg, "test-merkle-root").Return(&domain.AuxiliaryData{AuxID: "new-aux-id"}, nil).Once()

	req, _ := http.NewRequest("POST", "/protocol", nil)
	rr := httptest.NewRecorder()
	server.processAddAuxDataAction(rr, req, &protocolMsg)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockRepo.AssertExpectations(t)
	mockService.AssertExpectations(t)
	mockSigsum.AssertExpectations(t)
}

func TestProcessRevokeAuxDataAction(t *testing.T) {
	mockService := new(MockService)
	mockRepo := new(MockDBRepository)
	mockSigsum := new(sigsum.MockClient)
	server := &Server{service: mockService, repo: mockRepo, sigsum: mockSigsum}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	pubKeyStr := crypto.EncodePublicKey(pub)

	revokeAuxMsg := protocol.RevokeAuxDataMessage{Actor: "test-actor", AuxID: "test-aux-id", Time: "2024-01-01T00:00:00Z"}
	revokeAuxMsgJSON, _ := json.Marshal(revokeAuxMsg)

	signedMsg := protocol.SignedMessage{
		PKDContext: protocol.PKDContextV1, Action: "RevokeAuxData", Message: revokeAuxMsgJSON, RecentMerkleRoot: "test-merkle-root",
	}
	signedMsgBytes, _ := json.Marshal(signedMsg)
	signature := ed25519.Sign(priv, signedMsgBytes)
	signatureStr := base64.RawURLEncoding.EncodeToString(signature)

	protocolMsg := protocol.ProtocolMessage{
		PKDContext: protocol.PKDContextV1, Action: "RevokeAuxData", Message: revokeAuxMsgJSON, RecentMerkleRoot: "test-merkle-root", Signature: signatureStr,
	}

	mockRepo.On("ListKeysForActor", mock.Anything, "test-actor").Return([]*domain.PublicKey{{PublicKey: pubKeyStr}}, nil).Once()
	mockSigsum.On("SubmitMessage", mock.Anything, mock.Anything).Return("test-merkle-root", nil).Once()
	mockService.On("ProcessRevokeAuxData", mock.Anything, &revokeAuxMsg, "test-merkle-root").Return(nil).Once()

	req, _ := http.NewRequest("POST", "/protocol", nil)
	rr := httptest.NewRecorder()
	server.processRevokeAuxDataAction(rr, req, &protocolMsg)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockRepo.AssertExpectations(t)
	mockService.AssertExpectations(t)
	mockSigsum.AssertExpectations(t)
}

func TestProcessRevokeKeyAction(t *testing.T) {
	mockService := new(MockService)
	mockSigsum := new(sigsum.MockClient)
	mockRepo := new(MockDBRepository)

	server := &Server{
		service: mockService,
		sigsum:  mockSigsum,
		repo:    mockRepo,
	}

	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	pubKeyStr1 := crypto.EncodePublicKey(pub1)

	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	pubKeyStr2 := crypto.EncodePublicKey(pub2)

	revokeMsg := protocol.RevokeKeyMessage{
		Actor:     "test-actor",
		Time:      "2024-01-01T00:00:00Z",
		PublicKey: pubKeyStr2,
	}
	revokeMsgJSON, err := json.Marshal(revokeMsg)
	assert.NoError(t, err)

	signedMsg := protocol.SignedMessage{
		PKDContext:       protocol.PKDContextV1,
		Action:           "RevokeKey",
		Message:          revokeMsgJSON,
		RecentMerkleRoot: "test-merkle-root",
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	assert.NoError(t, err)

	signature := ed25519.Sign(priv1, signedMsgBytes)
	signatureStr := base64.RawURLEncoding.EncodeToString(signature)

	protocolMsg := protocol.ProtocolMessage{
		PKDContext:       protocol.PKDContextV1,
		Action:           "RevokeKey",
		Message:          revokeMsgJSON,
		RecentMerkleRoot: "test-merkle-root",
		Signature:        signatureStr,
	}

	existingKeys := []*domain.PublicKey{
		{PublicKey: pubKeyStr1},
		{PublicKey: pubKeyStr2},
	}
	mockRepo.On("ListKeysForActor", mock.Anything, "test-actor").Return(existingKeys, nil).Once()
	mockSigsum.On("SubmitMessage", mock.Anything, mock.Anything).Return("test-merkle-root", nil).Once()
	mockService.On("ProcessRevokeKey", mock.Anything, &revokeMsg, "test-merkle-root", mock.Anything).Return(nil).Once()

	req, err := http.NewRequest("POST", "/protocol", bytes.NewBuffer([]byte{}))
	assert.NoError(t, err)

	rr := httptest.NewRecorder()

	server.processRevokeKeyAction(rr, req, &protocolMsg)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockRepo.AssertExpectations(t)
	mockService.AssertExpectations(t)
	mockSigsum.AssertExpectations(t)
}

func TestProcessMoveIdentityAction(t *testing.T) {
	mockService := new(MockService)
	mockSigsum := new(sigsum.MockClient)
	mockRepo := new(MockDBRepository)

	server := &Server{
		service: mockService,
		sigsum:  mockSigsum,
		repo:    mockRepo,
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	pubKeyStr := crypto.EncodePublicKey(pub)

	moveMsg := protocol.MoveIdentityMessage{
		OldActor: "old-actor",
		NewActor: "new-actor",
		Time:     "2024-01-01T00:00:00Z",
	}
	moveMsgJSON, err := json.Marshal(moveMsg)
	assert.NoError(t, err)

	signedMsg := protocol.SignedMessage{
		PKDContext:       protocol.PKDContextV1,
		Action:           "MoveIdentity",
		Message:          moveMsgJSON,
		RecentMerkleRoot: "test-merkle-root",
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	assert.NoError(t, err)

	signature := ed25519.Sign(priv, signedMsgBytes)
	signatureStr := base64.RawURLEncoding.EncodeToString(signature)

	protocolMsg := protocol.ProtocolMessage{
		PKDContext:       protocol.PKDContextV1,
		Action:           "MoveIdentity",
		Message:          moveMsgJSON,
		RecentMerkleRoot: "test-merkle-root",
		Signature:        signatureStr,
	}

	existingKeys := []*domain.PublicKey{{PublicKey: pubKeyStr}}
	mockRepo.On("ListKeysForActor", mock.Anything, "old-actor").Return(existingKeys, nil).Once()
	mockSigsum.On("SubmitMessage", mock.Anything, mock.Anything).Return("test-merkle-root", nil).Once()
	mockService.On("ProcessMoveIdentity", mock.Anything, &moveMsg, "test-merkle-root").Return(nil).Once()

	req, err := http.NewRequest("POST", "/protocol", bytes.NewBuffer([]byte{}))
	assert.NoError(t, err)
	rr := httptest.NewRecorder()
	server.processMoveIdentityAction(rr, req, &protocolMsg)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockRepo.AssertExpectations(t)
	mockService.AssertExpectations(t)
	mockSigsum.AssertExpectations(t)
}

func TestProcessBurnDownAction(t *testing.T) {
	mockService := new(MockService)
	mockSigsum := new(sigsum.MockClient)
	mockRepo := new(MockDBRepository)

	server := &Server{
		service: mockService,
		sigsum:  mockSigsum,
		repo:    mockRepo,
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	pubKeyStr := crypto.EncodePublicKey(pub)

	burnMsg := protocol.BurnDownMessage{
		Actor:    "test-actor",
		Operator: "test-operator",
		Time:     "2024-01-01T00:00:00Z",
	}
	burnMsgJSON, err := json.Marshal(burnMsg)
	assert.NoError(t, err)

	signedMsg := protocol.SignedMessage{
		PKDContext:       protocol.PKDContextV1,
		Action:           "BurnDown",
		Message:          burnMsgJSON,
		RecentMerkleRoot: "test-merkle-root",
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	assert.NoError(t, err)

	signature := ed25519.Sign(priv, signedMsgBytes)
	signatureStr := base64.RawURLEncoding.EncodeToString(signature)

	protocolMsg := protocol.ProtocolMessage{
		PKDContext:       protocol.PKDContextV1,
		Action:           "BurnDown",
		Message:          burnMsgJSON,
		RecentMerkleRoot: "test-merkle-root",
		Signature:        signatureStr,
	}

	operatorKeys := []*domain.PublicKey{{PublicKey: pubKeyStr}}
	mockRepo.On("ListKeysForActor", mock.Anything, "test-operator").Return(operatorKeys, nil).Once()
	mockRepo.On("GetTOTPSecret", mock.Anything, "test-operator").Return(nil, nil).Once()
	mockSigsum.On("SubmitMessage", mock.Anything, mock.Anything).Return("test-merkle-root", nil).Once()
	mockService.On("ProcessBurnDown", mock.Anything, "test-actor", "test-merkle-root").Return(nil).Once()

	req, err := http.NewRequest("POST", "/protocol", bytes.NewBuffer([]byte{}))
	assert.NoError(t, err)
	rr := httptest.NewRecorder()
	server.processBurnDownAction(rr, req, &protocolMsg)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockRepo.AssertExpectations(t)
	mockService.AssertExpectations(t)
	mockSigsum.AssertExpectations(t)
}
