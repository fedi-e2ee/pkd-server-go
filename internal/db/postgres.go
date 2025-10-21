package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/jmoiron/sqlx"

	_ "github.com/jackc/pgx/v5/stdlib" // sqlx needs the stdlib driver
)

// PostgresRepository is a PostgreSQL implementation of the Repository and Transactioner interfaces.
type PostgresRepository struct {
	db *sqlx.DB
}

// DB returns the underlying sqlx.DB object. This is useful for running migrations in tests.
func (r *PostgresRepository) DB() *sqlx.DB {
	return r.db
}

// NewPostgresRepository creates a new PostgresRepository and connects to the database.
func NewPostgresRepository(ctx context.Context, dsn string) (*PostgresRepository, error) {
	db, err := sqlx.ConnectContext(ctx, "pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(1 * time.Minute)

	return &PostgresRepository{db: db}, nil
}

// BeginTx starts a new database transaction.
func (r *PostgresRepository) BeginTx(ctx context.Context) (domain.TransactionalRepository, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	return &PostgresTx{tx: tx}, nil
}

// Ping checks the database connection.
func (r *PostgresRepository) Ping(ctx context.Context) error {
	return r.db.PingContext(ctx)
}

// Close closes the database connection.
func (r *PostgresRepository) Close() error {
	return r.db.Close()
}

// FindActorByActorID retrieves an actor by their canonical Actor ID.
func (r *PostgresRepository) FindActorByActorID(ctx context.Context, actorID string) (*domain.Actor, error) {
	var actor domain.Actor
	query := `SELECT id, actor_id, is_fireproof, created_at, updated_at FROM actors WHERE actor_id = $1`
	err := r.db.GetContext(ctx, &actor, query, actorID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // Not found is not an error
		}
		return nil, fmt.Errorf("failed to find actor by actor_id %s: %w", actorID, err)
	}
	return &actor, nil
}

// IsFireproof checks if an actor has enabled the fireproof setting.
func (r *PostgresRepository) IsFireproof(ctx context.Context, actorID string) (bool, error) {
	var isFireproof bool
	query := `SELECT is_fireproof FROM actors WHERE actor_id = $1`
	err := r.db.GetContext(ctx, &isFireproof, query, actorID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil // An actor that doesn't exist is not fireproof.
		}
		return false, fmt.Errorf("failed to check fireproof status for actor %s: %w", actorID, err)
	}
	return isFireproof, nil
}

// SetFireproof updates the fireproof status for a given actor.
func (r *PostgresRepository) SetFireproof(ctx context.Context, actorID string, isFireproof bool) error {
	query := `UPDATE actors SET is_fireproof = $1, updated_at = NOW() WHERE actor_id = $2`
	result, err := r.db.ExecContext(ctx, query, isFireproof, actorID)
	if err != nil {
		return fmt.Errorf("failed to set fireproof status for actor %s: %w", actorID, err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected for actor %s: %w", actorID, err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("actor not found: %s", actorID)
	}
	return nil
}

// GetAllTlogEntries retrieves all entries from the transparency log.
func (r *PostgresRepository) GetAllTlogEntries(ctx context.Context) ([]*domain.TlogEntry, error) {
	var entries []*domain.TlogEntry
	query := `SELECT id, merkle_root, signed_message, public_key_hash, created_at FROM tlog_entries ORDER BY id ASC`
	err := r.db.SelectContext(ctx, &entries, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get all tlog entries: %w", err)
	}
	return entries, nil
}

// AddTlogEntry adds a new entry to the transparency log.
func (r *PostgresRepository) AddTlogEntry(ctx context.Context, merkleRoot []byte, signedMessage []byte, publicKeyHash []byte) error {
	query := `
		INSERT INTO tlog_entries (merkle_root, signed_message, public_key_hash, created_at)
		VALUES ($1, $2, $3, NOW())`
	_, err := r.db.ExecContext(ctx, query, merkleRoot, signedMessage, publicKeyHash)
	if err != nil {
		return fmt.Errorf("failed to insert tlog entry: %w", err)
	}
	return nil
}

// GetLatestMerkleRoot retrieves the most recent merkle_root from the public_keys table.
func (r *PostgresRepository) GetLatestMerkleRoot(ctx context.Context) (string, error) {
	var merkleRoot string
	query := `SELECT merkle_root FROM public_keys ORDER BY created_at DESC LIMIT 1`
	err := r.db.GetContext(ctx, &merkleRoot, query)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil // No keys yet, return empty string
		}
		return "", fmt.Errorf("failed to get latest merkle root: %w", err)
	}
	return merkleRoot, nil
}

// ListKeysForActor retrieves all non-revoked public keys for a given actor.
func (r *PostgresRepository) ListKeysForActor(ctx context.Context, actorID string) ([]*domain.PublicKey, error) {
	var keys []*domain.PublicKey
	query := `
		SELECT pk.id, pk.actor_id, pk.key_id, pk.public_key, pk.merkle_root, pk.created_at, pk.revoked_at, pk.revoke_root
		FROM public_keys pk
		JOIN actors a ON pk.actor_id = a.id
		WHERE a.actor_id = $1 AND pk.revoked_at IS NULL`
	err := r.db.SelectContext(ctx, &keys, query, actorID)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys for actor %s: %w", actorID, err)
	}
	return keys, nil
}

// FindKeyByKeyID retrieves a specific public key by its unique key_id.
func (r *PostgresRepository) FindKeyByKeyID(ctx context.Context, keyID string) (*domain.PublicKey, error) {
	var key domain.PublicKey
	query := `SELECT id, actor_id, key_id, public_key, merkle_root, created_at, revoked_at, revoke_root FROM public_keys WHERE key_id = $1`
	err := r.db.GetContext(ctx, &key, query, keyID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to find key by key_id %s: %w", keyID, err)
	}
	return &key, nil
}

// ListAuxDataForActor retrieves all non-revoked auxiliary data for a given actor.
func (r *PostgresRepository) ListAuxDataForActor(ctx context.Context, actorID string) ([]*domain.AuxiliaryData, error) {
	var auxData []*domain.AuxiliaryData
	query := `
		SELECT ad.id, ad.actor_id, ad.aux_id, ad.aux_type, ad.aux_data, ad.merkle_root, ad.created_at, ad.revoked_at, ad.revoke_root
		FROM auxiliary_data ad
		JOIN actors a ON ad.actor_id = a.id
		WHERE a.actor_id = $1 AND ad.revoked_at IS NULL`
	err := r.db.SelectContext(ctx, &auxData, query, actorID)
	if err != nil {
		return nil, fmt.Errorf("failed to list auxiliary data for actor %s: %w", actorID, err)
	}
	return auxData, nil
}

// FindAuxDataByAuxID retrieves a specific auxiliary data record by its unique aux_id.
func (r *PostgresRepository) FindAuxDataByAuxID(ctx context.Context, auxID string) (*domain.AuxiliaryData, error) {
	var aux domain.AuxiliaryData
	query := `SELECT id, actor_id, aux_id, aux_type, aux_data, merkle_root, created_at, revoked_at, revoke_root FROM auxiliary_data WHERE aux_id = $1`
	err := r.db.GetContext(ctx, &aux, query, auxID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to find auxiliary data by aux_id %s: %w", auxID, err)
	}
	return &aux, nil
}

// FindSymmetricKeysByMessageHash retrieves all symmetric keys associated with a given message hash.
func (r *PostgresRepository) FindSymmetricKeysByMessageHash(ctx context.Context, messageHash string) ([]*domain.SymmetricKey, error) {
	var keys []*domain.SymmetricKey
	query := `SELECT id, message_hash, attribute, key, created_at FROM symmetric_keys WHERE message_hash = $1`
	err := r.db.SelectContext(ctx, &keys, query, messageHash)
	if err != nil {
		return nil, fmt.Errorf("failed to find symmetric keys by message hash %s: %w", messageHash, err)
	}
	return keys, nil
}

// StoreMessage logs a raw protocol message to the database for archival and replay purposes.
func (r *PostgresRepository) StoreMessage(ctx context.Context, hash string, rawMessage []byte, decryptedMessage *protocol.ProtocolMessage) error {
	decryptedJSON, err := json.Marshal(decryptedMessage)
	if err != nil {
		return fmt.Errorf("failed to marshal decrypted message to JSON: %w", err)
	}

	query := `
		INSERT INTO message_logs (message_hash, encrypted_message, decrypted_message, created_at)
		VALUES ($1, $2, $3, NOW())`
	_, err = r.db.ExecContext(ctx, query, hash, rawMessage, decryptedJSON)
	if err != nil {
		return fmt.Errorf("failed to insert message log: %w", err)
	}
	return nil
}

// StoreTOTPSecret stores or updates an encrypted TOTP secret for an instance.
func (r *PostgresRepository) StoreTOTPSecret(ctx context.Context, instance string, encryptedSecret []byte) error {
	query := `
		INSERT INTO totp_secrets (instance, encrypted_secret, created_at, updated_at)
		VALUES ($1, $2, NOW(), NOW())
		ON CONFLICT (instance) DO UPDATE
		SET encrypted_secret = EXCLUDED.encrypted_secret, updated_at = NOW()`
	_, err := r.db.ExecContext(ctx, query, instance, encryptedSecret)
	if err != nil {
		return fmt.Errorf("failed to store TOTP secret for instance %s: %w", instance, err)
	}
	return nil
}

// GetTOTPSecret retrieves an encrypted TOTP secret for a given instance.
func (r *PostgresRepository) GetTOTPSecret(ctx context.Context, instance string) ([]byte, error) {
	var secret []byte
	query := `SELECT encrypted_secret FROM totp_secrets WHERE instance = $1`
	err := r.db.GetContext(ctx, &secret, query, instance)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get TOTP secret for instance %s: %w", instance, err)
	}
	return secret, nil
}

// DeleteTOTPSecret removes a TOTP secret for a given instance.
func (r *PostgresRepository) DeleteTOTPSecret(ctx context.Context, instance string) error {
	query := `DELETE FROM totp_secrets WHERE instance = $1`
	result, err := r.db.ExecContext(ctx, query, instance)
	if err != nil {
		return fmt.Errorf("failed to delete TOTP secret for instance %s: %w", instance, err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected for TOTP secret deletion: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("TOTP secret for instance %s not found", instance)
	}
	return nil
}

// --- Transactional Implementation ---

// PostgresTx implements the domain.TransactionalRepository for PostgreSQL.
type PostgresTx struct {
	tx *sqlx.Tx
}

// Commit commits the transaction.
func (tx *PostgresTx) Commit() error {
	return tx.tx.Commit()
}

// Rollback rolls back the transaction.
func (tx *PostgresTx) Rollback() error {
	return tx.tx.Rollback()
}

// GetOrCreateActor finds an actor or creates them if they don't exist.
func (tx *PostgresTx) GetOrCreateActor(ctx context.Context, actorID string) (*domain.Actor, error) {
	var actor domain.Actor
	query := `SELECT id, actor_id, is_fireproof, created_at, updated_at FROM actors WHERE actor_id = $1 FOR UPDATE`
	err := tx.tx.GetContext(ctx, &actor, query, actorID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			insertQuery := `INSERT INTO actors (actor_id) VALUES ($1) RETURNING id, actor_id, is_fireproof, created_at, updated_at`
			err = tx.tx.GetContext(ctx, &actor, insertQuery, actorID)
			if err != nil {
				return nil, fmt.Errorf("failed to create actor %s: %w", actorID, err)
			}
			return &actor, nil
		}
		return nil, fmt.Errorf("failed to find actor %s: %w", actorID, err)
	}
	return &actor, nil
}

// FindActorByActorID retrieves an actor by their canonical Actor ID within a transaction.
func (tx *PostgresTx) FindActorByActorID(ctx context.Context, actorID string) (*domain.Actor, error) {
	var actor domain.Actor
	query := `SELECT id, actor_id, is_fireproof, created_at, updated_at FROM actors WHERE actor_id = $1`
	err := tx.tx.GetContext(ctx, &actor, query, actorID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find actor by actor_id %s: %w", actorID, err)
	}
	return &actor, nil
}

// ActorExists checks if an actor with the given ID exists.
func (tx *PostgresTx) ActorExists(ctx context.Context, actorID string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM actors WHERE actor_id = $1)`
	err := tx.tx.GetContext(ctx, &exists, query, actorID)
	if err != nil {
		return false, fmt.Errorf("failed to check for existing actor ID: %w", err)
	}
	return exists, nil
}

// UpdateActorID atomically renames an actor.
func (tx *PostgresTx) UpdateActorID(ctx context.Context, oldActorID, newActorID string) (int64, error) {
	query := `UPDATE actors SET actor_id = $1, updated_at = NOW() WHERE actor_id = $2`
	result, err := tx.tx.ExecContext(ctx, query, newActorID, oldActorID)
	if err != nil {
		return 0, fmt.Errorf("failed to update actor ID from %s to %s: %w", oldActorID, newActorID, err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected for move identity: %w", err)
	}
	return rowsAffected, nil
}

// InsertPublicKey adds a new public key record.
func (tx *PostgresTx) InsertPublicKey(ctx context.Context, key *domain.PublicKey) (*domain.PublicKey, error) {
	query := `
		INSERT INTO public_keys (actor_id, key_id, public_key, merkle_root, created_at)
		VALUES ($1, $2, $3, $4, NOW()) RETURNING id, created_at`
	err := tx.tx.QueryRowxContext(ctx, query, key.ActorID, key.KeyID, key.PublicKey, key.MerkleRoot).Scan(&key.ID, &key.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to insert new public key: %w", err)
	}
	return key, nil
}

// FindKeyToRevoke finds a public key for a given actor that is eligible for revocation.
func (tx *PostgresTx) FindKeyToRevoke(ctx context.Context, actorID, publicKey string) (*domain.PublicKey, error) {
	var keyToRevoke domain.PublicKey
	query := `
		SELECT pk.id FROM public_keys pk
		JOIN actors a ON pk.actor_id = a.id
		WHERE a.actor_id = $1 AND pk.public_key = $2 AND pk.revoked_at IS NULL`
	err := tx.tx.GetContext(ctx, &keyToRevoke, query, actorID, publicKey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // Not found is okay
		}
		return nil, fmt.Errorf("failed to find key to revoke: %w", err)
	}
	return &keyToRevoke, nil
}

// RevokeKey marks a public key as revoked.
func (tx *PostgresTx) RevokeKey(ctx context.Context, keyID int64, revokeRoot string) error {
	query := `UPDATE public_keys SET revoked_at = NOW(), revoke_root = $1 WHERE id = $2`
	_, err := tx.tx.ExecContext(ctx, query, revokeRoot, keyID)
	if err != nil {
		return fmt.Errorf("failed to execute revoke key query: %w", err)
	}
	return nil
}

// GetMessageHashesForActor retrieves all message hashes (merkle roots) for an actor's keys.
func (tx *PostgresTx) GetMessageHashesForActor(ctx context.Context, actorID int64) ([]string, error) {
	var messageHashes []string
	query := `
		SELECT merkle_root FROM public_keys WHERE actor_id = $1
		UNION
		SELECT revoke_root FROM public_keys WHERE actor_id = $1 AND revoke_root IS NOT NULL`
	if err := tx.tx.SelectContext(ctx, &messageHashes, query, actorID); err != nil {
		return nil, fmt.Errorf("failed to gather message hashes for actor %d: %w", actorID, err)
	}
	return messageHashes, nil
}

// RevokeAllKeysForActor marks all of an actor's keys as revoked.
func (tx *PostgresTx) RevokeAllKeysForActor(ctx context.Context, actorID int64, merkleRoot string) error {
	query := `UPDATE public_keys SET revoked_at = NOW(), revoke_root = $1 WHERE actor_id = $2 AND revoked_at IS NULL`
	if _, err := tx.tx.ExecContext(ctx, query, merkleRoot, actorID); err != nil {
		return fmt.Errorf("failed to revoke keys for actor %d: %w", actorID, err)
	}
	return nil
}

// InsertAuxData adds a new auxiliary data record.
func (tx *PostgresTx) InsertAuxData(ctx context.Context, aux *domain.AuxiliaryData) (*domain.AuxiliaryData, error) {
	query := `
		INSERT INTO auxiliary_data (actor_id, aux_id, aux_type, aux_data, merkle_root, created_at)
		VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING id, created_at`
	err := tx.tx.QueryRowxContext(ctx, query, aux.ActorID, aux.AuxID, aux.AuxType, aux.AuxData, aux.MerkleRoot).Scan(&aux.ID, &aux.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to insert new auxiliary data: %w", err)
	}
	return aux, nil
}

// RevokeAuxData marks an auxiliary data record as revoked.
func (tx *PostgresTx) RevokeAuxData(ctx context.Context, actorID, auxID, revokeRoot string) (int64, error) {
	query := `
		UPDATE auxiliary_data ad
		SET revoked_at = NOW(), revoke_root = $1
		FROM actors a
		WHERE ad.actor_id = a.id
		  AND a.actor_id = $2
		  AND ad.aux_id = $3
		  AND ad.revoked_at IS NULL`
	result, err := tx.tx.ExecContext(ctx, query, revokeRoot, actorID, auxID)
	if err != nil {
		return 0, fmt.Errorf("failed to execute revoke auxiliary data query: %w", err)
	}
	return result.RowsAffected()
}

// StoreSymmetricKeys stores a batch of symmetric keys.
func (tx *PostgresTx) StoreSymmetricKeys(ctx context.Context, messageHash string, keys map[string][]byte) (err error) {
	stmt, err := tx.tx.PreparexContext(ctx, `INSERT INTO symmetric_keys (message_hash, attribute, key, created_at) VALUES ($1, $2, $3, NOW())`)
	if err != nil {
		return fmt.Errorf("failed to prepare symmetric key statement: %w", err)
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close symmetric key statement: %w", closeErr)
		}
	}()

	for attribute, key := range keys {
		if _, err := stmt.ExecContext(ctx, messageHash, attribute, key); err != nil {
			return fmt.Errorf("failed to insert symmetric key for attribute %s: %w", attribute, err)
		}
	}
	return nil
}

// DeleteSymmetricKeysByHashes deletes symmetric keys based on a list of message hashes.
func (tx *PostgresTx) DeleteSymmetricKeysByHashes(ctx context.Context, hashes []string) error {
	if len(hashes) == 0 {
		return nil
	}
	query, args, err := sqlx.In("DELETE FROM symmetric_keys WHERE message_hash IN (?)", hashes)
	if err != nil {
		return fmt.Errorf("failed to construct IN query for crypto-shredding: %w", err)
	}
	query = tx.tx.Rebind(query)
	if _, err := tx.tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("failed to delete symmetric keys: %w", err)
	}
	return nil
}
