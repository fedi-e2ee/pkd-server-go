// This package contains the main process for the Public Key Directory server software.
// It exposes an HTTP server that routes calls to code inside ../internal/.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/fedi-e2ee/pkd-server-go/internal/api"
	"github.com/fedi-e2ee/pkd-server-go/internal/checkpoint"
	"github.com/fedi-e2ee/pkd-server-go/internal/config"
	"github.com/fedi-e2ee/pkd-server-go/internal/auxvalidator"
	"github.com/fedi-e2ee/pkd-server-go/internal/db"
	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	"github.com/fedi-e2ee/pkd-server-go/internal/auxdata"
	"github.com/fedi-e2ee/pkd-server-go/internal/sigsum"
)

func main() {
	// We log to STDOUT by default
	logger := log.New(os.Stdout, "pkd-server: ", log.LstdFlags|log.Lshortfile)

	// Load configuration file or bail out
	cfg, err := config.LoadAndValidate("")
	if err != nil {
		logger.Fatalf("Failed to load configuration: %v", err)
		os.Exit(1)
	}
	ctx := context.Background()

	// Initialize the database repository
	var repo db.Repository
	logger.Printf("Using database driver: %s, DSN: %s", cfg.Database.Driver, cfg.Database.DSN)
	switch cfg.Database.Driver {
	case "sqlite":
		repo, err = db.NewSQLiteRepository(ctx, cfg.Database.DSN)
	case "postgres":
		repo, err = db.NewPostgresRepository(ctx, cfg.Database.DSN)
	default:
		logger.Fatalf("Unsupported database driver: %s", cfg.Database.Driver)
	}
	if err != nil {
		logger.Fatalf("Failed to connect to the database: %v", err)
		os.Exit(1)
	}
	defer func() {
		if err := repo.Close(); err != nil {
			logger.Printf("Error closing repository: %v", err)
			os.Exit(1)
		}
	}()

	// Ping the database to verify the connection
	if err := repo.Ping(ctx); err != nil {
		logger.Fatalf("Failed to ping the database: %v", err)
	}
	logger.Println("Successfully connected to the database.")

	// Initialize the domain service
	// Register and enable the desired AuxData plugins.
	//
	// TODO: Replace this with configuration-driven loading
	enabledValidators := []auxvalidator.AuxDataValidator{
		auxdata.NewAgeValidator(),
		auxdata.NewSSHValidator(),
	}
	service := domain.NewPKDService(repo, enabledValidators)

	// Initialize the SigSum client
	sigsumClient := sigsum.NewHTTPClient(cfg.SigSum.URL)
	logger.Printf("Using SigSum client, configured with URL: %s", cfg.SigSum.URL)

	// Initialize the Router
	runtimeState := &api.RuntimeState{
		Repo:           repo,
		Service:        service,
		SigsumClient:   sigsumClient,
		Logger:         logger,
		HPKEPublicKey:  cfg.Server.HPKEPublicKey,
		HPKEPrivateKey: cfg.Server.HPKEPrivateKey,
		Config:         cfg,
		DB:             repo.DB(),
	}
	router := api.NewRouter(runtimeState)

	// Start the checkpoint scheduler
	scheduler := checkpoint.NewScheduler(repo, cfg, logger)
	scheduler.Start()
	defer scheduler.Stop()

	// Start the server
	serverAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	logger.Printf("Starting server on %s", serverAddr)
	if err := http.ListenAndServe(serverAddr, router); err != nil {
		logger.Fatalf("Server failed to start: %v", err)
		os.Exit(1)
	}
}
