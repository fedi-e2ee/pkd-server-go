package testutil

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/fedi-e2ee/pkd-server-go/internal/api"
	"github.com/fedi-e2ee/pkd-server-go/internal/auth"
	"github.com/gowebpki/jcs"
	"github.com/fedi-e2ee/pkd-server-go/internal/config"
	"github.com/fedi-e2ee/pkd-server-go/internal/crypto"
	"github.com/fedi-e2ee/pkd-server-go/internal/db"
	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/fedi-e2ee/pkd-server-go/internal/sigsum"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // driver for CREATE DATABASE
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestInstance encapsulates all the components of a single, isolated test environment.
type TestInstance struct {
	T            *testing.T
	Ctx          context.Context
	Server       *httptest.Server
	Repo         db.Repository
	Service      *domain.PKDService
	SigsumClient *sigsum.MockClient
	PubKey       kem.PublicKey
	postgresDSN  string // Keep track of the DSN for teardown
	dbName       string // Keep track of the db name for teardown
	Config       *config.Config
	Router       http.Handler
	DB           *sqlx.DB
	Logger       *log.Logger
	TokenService auth.TokenService
}

// getProjectRoot returns the absolute path to the project's root directory.
func getProjectRoot() (string, error) {
	_, b, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("could not get caller information")
	}
	// b is the path to this file (helpers.go). We want to go up two directories
	// (internal/testutil -> internal -> project root).
	return filepath.Join(filepath.Dir(b), "..", ".."), nil
}

// NewTestInstance creates a new, completely isolated test environment.
func NewTestInstance(t *testing.T) (*TestInstance, error) {
	t.Helper()

	rootPath, err := getProjectRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to get project root: %w", err)
	}

	ctx := context.Background()
	dsn := os.Getenv("TEST_DATABASE_DSN")

	var repo db.Repository
	var sqlxDB *sqlx.DB
	var pgDSN, dbName string

	if dsn != "" {
		// --- PostgreSQL Setup ---
		dbConn, err := sql.Open("postgres", dsn)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to postgres for db creation: %w", err)
		}
		defer func() {
			_ = dbConn.Close()
		}()

		dbName = "test_db_" + randomString(16)
		_, err = dbConn.Exec(fmt.Sprintf("CREATE DATABASE %s", dbName))
		if err != nil {
			return nil, fmt.Errorf("failed to create test database: %w", err)
		}

		parsedDSN, err := url.Parse(dsn)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DSN: %w", err)
		}
		parsedDSN.Path = "/" + dbName
		pgDSN = parsedDSN.String()

		pgRepo, err := db.NewPostgresRepository(ctx, pgDSN)
		if err != nil {
			return nil, fmt.Errorf("could not connect to test postgres db: %w", err)
		}
		repo = pgRepo
		sqlxDB = pgRepo.DB()

		migrationsPath := filepath.Join(rootPath, "sql", "pgsql")
		migrator, err := migrate.New("file://"+migrationsPath, pgDSN)
		if err != nil {
			return nil, fmt.Errorf("could not create migrator: %w", err)
		}

		err = migrator.Up()
		if err != nil {
			return nil, fmt.Errorf("could not run up migrations: %w", err)
		}
	} else {
		// --- SQLite Setup ---
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "test.db")
		sqliteDSN := fmt.Sprintf("file:%s?_foreign_keys=on", dbPath)

		sqliteRepo, err := db.NewSQLiteRepository(ctx, sqliteDSN)
		if err != nil {
			return nil, fmt.Errorf("could not connect to sqlite: %w", err)
		}
		repo = sqliteRepo
		sqlxDB = sqliteRepo.DB()

		schemaPath := filepath.Join(rootPath, "sql", "sqlite", "sqlite_schema.sql")
		schema, err := os.ReadFile(schemaPath)
		if err != nil {
			return nil, fmt.Errorf("could not read sqlite schema file '%s': %w", schemaPath, err)
		}
		_, err = sqliteRepo.DB().ExecContext(ctx, string(schema))
		if err != nil {
			return nil, fmt.Errorf("could not apply sqlite schema: %w", err)
		}
	}

	// --- Common Test Server Setup ---
	kemID := hpke.KEM_X25519_HKDF_SHA256
	pk, sk, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate HPKE keys: %w", err)
	}

	_, signingPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing key: %w", err)
	}

	keyFile, err := os.CreateTemp(t.TempDir(), "test.key")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp key file: %w", err)
	}
	_ = keyFile.Close()

	cfg := &config.Config{
		Server: config.Server{
			PrivateKey: crypto.EncodePrivateKey(signingPrivKey),
			KeyFile: config.KeyFile{
				Path:            keyFile.Name(),
				Password:        "test-password",
				Argon2idTime:    1,
				Argon2idMemory:  1024,
				Argon2idThreads: 1,
			},
		},
		Peers: make(map[string]config.Peer),
		Test: config.Test{
			AllowPrivateIPs: true,
		},
	}

	service := domain.NewPKDService(repo, nil)
	sigsumClient := &sigsum.MockClient{}
	sigsumClient.On("SubmitMessage", mock.Anything, mock.Anything).Return("merkle-root", nil)
	logger := log.New(os.Stdout, "TEST_PKD_SERVER ", log.LstdFlags|log.Lshortfile)

	keyManager, err := auth.NewFileKeyManager(
		cfg.Server.KeyFile.Path,
		[]byte(cfg.Server.KeyFile.Password),
		1, 1024, 1,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create key manager for test: %w", err)
	}
	tokenService := auth.NewPasetoTokenService(keyManager, cfg, sqlxDB)

	runtimeState := &api.RuntimeState{
		Repo:           repo,
		Service:        service,
		SigsumClient:   sigsumClient,
		Logger:         logger,
		HPKEPublicKey:  pk,
		HPKEPrivateKey: sk,
		Config:         cfg,
		DB:             sqlxDB,
	}
	router := api.NewRouter(runtimeState)
	server := httptest.NewServer(router)

	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse test server URL: %w", err)
	}
	cfg.Server.Host = parsedURL.Hostname()
	port, _ := strconv.Atoi(parsedURL.Port())
	cfg.Server.Port = port

	return &TestInstance{
		T:            t,
		Ctx:          ctx,
		Server:       server,
		Repo:         repo,
		Service:      service,
		SigsumClient: sigsumClient,
		PubKey:       pk,
		postgresDSN:  dsn,
		dbName:       dbName,
		Config:       cfg,
		Router:       router,
		DB:           sqlxDB,
		Logger:       logger,
		TokenService: tokenService,
	}, nil
}

// Teardown cleans up all resources used by the TestInstance.
func (ti *TestInstance) Teardown() {
	ti.T.Helper()
	ti.Server.Close()
	if err := ti.Repo.Close(); err != nil {
		ti.Logger.Printf("Error closing repository in teardown: %v", err)
	}

	if ti.postgresDSN != "" && ti.dbName != "" {
		db, err := sqlx.Connect("postgres", ti.postgresDSN)
		require.NoError(ti.T, err, "failed to connect to postgres for db teardown")
		defer func() {
			if err := db.Close(); err != nil {
				ti.Logger.Printf("Error closing teardown db connection: %v", err)
			}
		}()

		_, err = db.Exec(fmt.Sprintf("SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.datname = '%s' AND pid <> pg_backend_pid()", ti.dbName))
		if err != nil {
			log.Printf("WARN: could not terminate connections to test database '%s': %v", ti.dbName, err)
		}

		_, err = db.Exec(fmt.Sprintf("DROP DATABASE %s", ti.dbName))
		require.NoError(ti.T, err, "failed to drop test database")
	}
}

// GetPeerConfig returns a config.Peer struct for the test instance.
func (ti *TestInstance) GetPeerConfig() config.Peer {
	privKeyBytes, err := base64.RawURLEncoding.DecodeString(ti.Config.Server.PrivateKey)
	require.NoError(ti.T, err)
	pubKey := ed25519.PrivateKey(privKeyBytes).Public().(ed25519.PublicKey)
	return config.Peer{
		PublicKey: base64.RawURLEncoding.EncodeToString(pubKey),
	}
}

// AddSampleKey creates a new keypair and adds it to the server for the given user.
func AddSampleKey(t *testing.T, ti *TestInstance, username string, signingKey ed25519.PrivateKey, symKeys map[string]string) (string, ed25519.PublicKey, ed25519.PrivateKey, error) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, nil, err
	}

	addKeyMsg := protocol.AddKeyMessage{
		Actor:     username,
		Time:      time.Now().UTC().Format(time.RFC3339),
		PublicKey: crypto.EncodePublicKey(pub),
	}
	addKeyMsgBytes, err := json.Marshal(addKeyMsg)
	if err != nil {
		return "", nil, nil, err
	}

	if signingKey == nil {
		signingKey = priv
	}

	signedMsg := protocol.SignedMessage{
		PKDContext: "https://github.com/fedi-e2ee/public-key-directory/v1",
		Action:     "AddKey",
		Message:    addKeyMsgBytes,
	}
	tempBytes, err := json.Marshal(signedMsg)
	if err != nil {
		return "", nil, nil, err
	}
	signedMsgBytes, err := jcs.Transform(tempBytes)
	if err != nil {
		return "", nil, nil, err
	}
	signature, err := crypto.SignMessage(signingKey, signedMsgBytes)
	if err != nil {
		return "", nil, nil, err
	}

	protoMsg := protocol.ProtocolMessage{
		PKDContext:    signedMsg.PKDContext,
		Action:        signedMsg.Action,
		Message:       signedMsg.Message,
		Signature:     signature,
		SymmetricKeys: symKeys,
	}
	protoMsgBytes, err := json.Marshal(protoMsg)
	if err != nil {
		return "", nil, nil, err
	}

	req := httptest.NewRequest("POST", "/protocol", bytes.NewReader(protoMsgBytes))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	ti.Router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		return "", nil, nil, fmt.Errorf("failed to add key, status: %d, body: %s", resp.Code, resp.Body.String())
	}

	var addKeyResp map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&addKeyResp); err != nil {
		return "", nil, nil, err
	}

	return addKeyResp["key_id"], pub, priv, nil
}

// randomString generates a random string of a given length.
func randomString(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return strings.ToLower(fmt.Sprintf("%x", b))
}
