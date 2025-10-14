package checkpoint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/fedi-e2ee/pkd-server-go/internal/config"
	"github.com/fedi-e2ee/pkd-server-go/internal/crypto"
	"github.com/fedi-e2ee/pkd-server-go/internal/db"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
)

// Scheduler manages automated checkpoints.
type Scheduler struct {
	repo   db.Repository
	config *config.Config
	logger *log.Logger
	ticker *time.Ticker
	done   chan bool
}

// NewScheduler creates a new checkpoint scheduler.
func NewScheduler(repo db.Repository, cfg *config.Config, logger *log.Logger) *Scheduler {
	return &Scheduler{
		repo:   repo,
		config: cfg,
		logger: logger,
		done:   make(chan bool),
	}
}

// Start begins the checkpoint scheduling loop.
func (s *Scheduler) Start() {
	if s.config.CheckpointPolicy.Interval == "" {
		s.logger.Println("Checkpoint policy interval not set, scheduler will not run.")
		return
	}

	interval, err := time.ParseDuration(s.config.CheckpointPolicy.Interval)
	if err != nil {
		s.logger.Printf("Invalid checkpoint policy interval: %v", err)
		return
	}

	s.ticker = time.NewTicker(interval)
	s.logger.Printf("Checkpoint scheduler started with interval %s", interval)

	go func() {
		for {
			select {
			case <-s.done:
				return
			case <-s.ticker.C:
				s.logger.Println("Triggering scheduled checkpoint...")
				s.triggerCheckpoint()
			}
		}
	}()
}

// Stop halts the checkpoint scheduler.
func (s *Scheduler) Stop() {
	if s.ticker != nil {
		s.ticker.Stop()
	}
	s.done <- true
	s.logger.Println("Checkpoint scheduler stopped.")
}

// triggerCheckpoint performs the actual checkpoint operation.
func (s *Scheduler) triggerCheckpoint() {
	ctx := context.Background()
	target := s.config.CheckpointPolicy.TargetDirectory
	if target == "" {
		s.logger.Println("No target directory configured for checkpoint policy.")
		return
	}

	latestRoot, err := s.repo.GetLatestMerkleRoot(ctx)
	if err != nil {
		s.logger.Printf("Error getting latest merkle root for checkpoint: %v", err)
		return
	}

	checkpointMsg := protocol.CheckpointMessage{
		Time:          time.Now().UTC().Format(time.RFC3339),
		FromDirectory: fmt.Sprintf("http://%s:%d", s.config.Server.Host, s.config.Server.Port),
		FromRoot:      latestRoot,
		ToDirectory:   target,
	}
	checkpointMsgBytes, err := json.Marshal(checkpointMsg)
	if err != nil {
		s.logger.Printf("Error marshalling checkpoint message: %v", err)
		return
	}

	protoMsg := protocol.ProtocolMessage{
		PKDContext: "https://github.com/fedi-e2ee/public-key-directory/v1",
		Action:     "Checkpoint",
		Message:    checkpointMsgBytes,
	}

	privateKeyBytes, err := base64.StdEncoding.DecodeString(s.config.Server.PrivateKey)
	if err != nil {
		s.logger.Printf("Error decoding server private key for checkpoint: %v", err)
		return
	}
	privateKey := ed25519.PrivateKey(privateKeyBytes)

	signedMsg := protocol.SignedMessage{
		PKDContext: protoMsg.PKDContext,
		Action:     protoMsg.Action,
		Message:    protoMsg.Message,
	}
	signedMsgBytes, err := json.Marshal(signedMsg)
	if err != nil {
		s.logger.Printf("Error marshalling signed message for checkpoint: %v", err)
		return
	}

	signature, err := crypto.SignMessage(privateKey, signedMsgBytes)
	if err != nil {
		s.logger.Printf("Error signing checkpoint message: %v", err)
		return
	}
	protoMsg.Signature = signature

	finalMsgBytes, err := json.Marshal(protoMsg)
	if err != nil {
		s.logger.Printf("Error marshalling final checkpoint message: %v", err)
		return
	}

	resp, err := http.Post(target+"/protocol", "application/json", bytes.NewBuffer(finalMsgBytes))
	if err != nil {
		s.logger.Printf("Error sending checkpoint to peer %s: %v", target, err)
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Printf("Error closing response body from peer %s: %v", target, err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		s.logger.Printf("Peer server %s responded with status %d for checkpoint", target, resp.StatusCode)
		return
	}

	s.logger.Printf("Successfully sent checkpoint to %s", target)
}
