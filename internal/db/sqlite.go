package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

// SQLiteRepository is a SQLite implementation of the Repository and Transactioner interfaces.
type SQLiteRepository struct {
	db *sqlx.DB
}

// NewSQLiteRepository creates a new SQLiteRepository.
// It connects to an in-memory database if dsn is empty, otherwise uses the provided DSN.
func NewSQLiteRepository(ctx context.Context, dsn string) (*SQLiteRepository, error) {
	if dsn == "" {
		dsn = "file::memory:?cache=shared&_foreign_keys=on"
	}
	db, err := sqlx.ConnectContext(ctx, "sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to sqlite: %w", err)
	}
	// When using a file-based database, we don't want to limit connections.
	// In-memory still needs this to ensure the same connection is shared.
	if dsn == "file::memory:?cache=shared&_foreign_keys=on" {
		db.SetMaxOpenConns(1)
	}
	return &SQLiteRepository{db: db}, nil
}

// DB returns the underlying sqlx.DB object. This is useful for running migrations in tests.
func (r *SQLiteRepository) DB() *sqlx.DB {
	return r.db
}

// BeginTx starts a new database transaction.
func (r *SQLiteRepository) BeginTx(ctx context.Context) (domain.TransactionalRepository, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	return &SQLiteTx{tx: tx}, nil
}

// Ping checks the database connection.
func (r *SQLiteRepository) Ping(ctx context.Context) error {
	return r.db.PingContext(ctx)
}

// Close closes the database connection.
func (r *SQLiteRepository) Close() error {
	return r.db.Close()
}

// FindActorByActorID retrieves an actor by their canonical Actor ID.
func (r *SQLiteRepository) FindActorByActorID(ctx context.Context, actorID string) (*domain.Actor, error) {
	var actor domain.Actor
	query := `SELECT id, actor_id, is_fireproof, created_at, updated_at FROM actors WHERE actor_id = ?`
	err := r.db.GetContext(ctx, &actor, query, actorID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find actor by actor_id %s: %w", actorID, err)
	}
	return &actor, nil
}

// IsFireproof checks if an actor has enabled the fireproof setting.
func (r *SQLiteRepository) IsFireproof(ctx context.Context, actorID string) (bool, error) {
	var isFireproof bool
	query := `SELECT is_fireproof FROM actors WHERE actor_id = ?`
	err := r.db.GetContext(ctx, &isFireproof, query, actorID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check fireproof status for actor %s: %w", actorID, err)
	}
	return isFireproof, nil
}

// SetFireproof updates the fireproof status for a given actor.
func (r *SQLiteRepository) SetFireproof(ctx context.Context, actorID string, isFireproof bool) error {
	query := `UPDATE actors SET is_fireproof = ?, updated_at = CURRENT_TIMESTAMP WHERE actor_id = ?`
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

// GetLatestMerkleRoot retrieves the most recent merkle_root from the public_keys table.
func (r *SQLiteRepository) GetLatestMerkleRoot(ctx context.Context) (string, error) {
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
func (r *SQLiteRepository) ListKeysForActor(ctx context.Context, actorID string) ([]*domain.PublicKey, error) {
	var keys []*domain.PublicKey
	query := `
		SELECT pk.id, pk.actor_id, pk.key_id, pk.public_key, pk.merkle_root, pk.created_at, pk.revoked_at, pk.revoke_root
		FROM public_keys pk
		JOIN actors a ON pk.actor_id = a.id
		WHERE a.actor_id = ? AND pk.revoked_at IS NULL`
	err := r.db.SelectContext(ctx, &keys, query, actorID)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys for actor %s: %w", actorID, err)
	}
	return keys, nil
}

// FindKeyByKeyID retrieves a specific public key by its unique key_id.
func (r *SQLiteRepository) FindKeyByKeyID(ctx context.Context, keyID string) (*domain.PublicKey, error) {
	var key domain.PublicKey
	query := `SELECT id, actor_id, key_id, public_key, merkle_root, created_at, revoked_at, revoke_root FROM public_keys WHERE key_id = ?`
	err := r.db.GetContext(ctx, &key, query, keyID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find key by key_id %s: %w", keyID, err)
	}
	return &key, nil
}

// ListAuxDataForActor retrieves all non-revoked auxiliary data for a given actor.
func (r *SQLiteRepository) ListAuxDataForActor(ctx context.Context, actorID string) ([]*domain.AuxiliaryData, error) {
	var auxData []*domain.AuxiliaryData
	query := `
		SELECT ad.id, ad.actor_id, ad.aux_id, ad.aux_type, ad.aux_data, ad.merkle_root, ad.created_at, ad.revoked_at, ad.revoke_root
		FROM auxiliary_data ad
		JOIN actors a ON ad.actor_id = a.id
		WHERE a.actor_id = ? AND ad.revoked_at IS NULL`
	err := r.db.SelectContext(ctx, &auxData, query, actorID)
	if err != nil {
		return nil, fmt.Errorf("failed to list auxiliary data for actor %s: %w", actorID, err)
	}
	return auxData, nil
}

// FindAuxDataByAuxID retrieves a specific auxiliary data record by its unique aux_id.
func (r *SQLiteRepository) FindAuxDataByAuxID(ctx context.Context, auxID string) (*domain.AuxiliaryData, error) {
	var aux domain.AuxiliaryData
	query := `SELECT id, actor_id, aux_id, aux_type, aux_data, merkle_root, created_at, revoked_at, revoke_root FROM auxiliary_data WHERE aux_id = ?`
	err := r.db.GetContext(ctx, &aux, query, auxID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find auxiliary data by aux_id %s: %w", auxID, err)
	}
	return &aux, nil
}

// FindSymmetricKeysByMessageHash retrieves all symmetric keys associated with a given message hash.
func (r *SQLiteRepository) FindSymmetricKeysByMessageHash(ctx context.Context, messageHash string) ([]*domain.SymmetricKey, error) {
	var keys []*domain.SymmetricKey
	query := `SELECT id, message_hash, attribute, key, created_at FROM symmetric_keys WHERE message_hash = ?`
	err := r.db.SelectContext(ctx, &keys, query, messageHash)
	if err != nil {
		return nil, fmt.Errorf("failed to find symmetric keys by message hash %s: %w", messageHash, err)
	}
	return keys, nil
}

// StoreMessage logs a raw protocol message to the database for archival and replay purposes.
func (r *SQLiteRepository) StoreMessage(ctx context.Context, hash string, rawMessage []byte, decryptedMessage *protocol.ProtocolMessage) error {
	decryptedJSON, err := json.Marshal(decryptedMessage)
	if err != nil {
		return fmt.Errorf("failed to marshal decrypted message to JSON: %w", err)
	}
	query := `INSERT INTO message_logs (message_hash, encrypted_message, decrypted_message) VALUES (?, ?, ?)`
	_, err = r.db.ExecContext(ctx, query, hash, rawMessage, decryptedJSON)
	if err != nil {
		return fmt.Errorf("failed to insert message log: %w", err)
	}
	return nil
}

// StoreTOTPSecret stores or updates an encrypted TOTP secret for an instance.
func (r *SQLiteRepository) StoreTOTPSecret(ctx context.Context, instance string, encryptedSecret []byte) error {
	query := `
		INSERT INTO totp_secrets (instance, encrypted_secret, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(instance) DO UPDATE SET
			encrypted_secret = excluded.encrypted_secret,
			updated_at = CURRENT_TIMESTAMP`
	_, err := r.db.ExecContext(ctx, query, instance, encryptedSecret)
	if err != nil {
		return fmt.Errorf("failed to store TOTP secret for instance %s: %w", instance, err)
	}
	return nil
}

// GetTOTPSecret retrieves an encrypted TOTP secret for a given instance.
func (r *SQLiteRepository) GetTOTPSecret(ctx context.Context, instance string) ([]byte, error) {
	var secret []byte
	query := `SELECT encrypted_secret FROM totp_secrets WHERE instance = ?`
	err := r.db.GetContext(ctx, &secret, query, instance)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get TOTP secret for instance %s: %w", instance, err)
	}
	return secret, nil
}

// DeleteTOTPSecret removes a TOTP secret for a given instance.
func (r *SQLiteRepository) DeleteTOTPSecret(ctx context.Context, instance string) error {
	query := `DELETE FROM totp_secrets WHERE instance = ?`
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

// SQLiteTx implements the domain.TransactionalRepository for SQLite.
type SQLiteTx struct {
	tx *sqlx.Tx
}

// Commit commits the transaction.
func (tx *SQLiteTx) Commit() error {
	return tx.tx.Commit()
}

// Rollback rolls back the transaction.
func (tx *SQLiteTx) Rollback() error {
	return tx.tx.Rollback()
}

func (tx *SQLiteTx) findActorByID(ctx context.Context, id int64) (*domain.Actor, error) {
	var actor domain.Actor
	query := `SELECT id, actor_id, is_fireproof, created_at, updated_at FROM actors WHERE id = ?`
	err := tx.tx.GetContext(ctx, &actor, query, id)
	if err != nil {
		return nil, fmt.Errorf("failed to find actor by id %d: %w", id, err)
	}
	return &actor, nil
}

func (tx *SQLiteTx) GetOrCreateActor(ctx context.Context, actorID string) (*domain.Actor, error) {
	var actor domain.Actor
	query := `SELECT id, actor_id, is_fireproof, created_at, updated_at FROM actors WHERE actor_id = ?`
	err := tx.tx.GetContext(ctx, &actor, query, actorID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			insertQuery := `INSERT INTO actors (actor_id) VALUES (?)`
			result, err := tx.tx.ExecContext(ctx, insertQuery, actorID)
			if err != nil {
				return nil, fmt.Errorf("failed to create actor %s: %w", actorID, err)
			}
			id, err := result.LastInsertId()
			if err != nil {
				return nil, fmt.Errorf("failed to get last insert ID for actor %s: %w", actorID, err)
			}
			return tx.findActorByID(ctx, id)
		}
		return nil, fmt.Errorf("failed to find actor %s: %w", actorID, err)
	}
	return &actor, nil
}

func (tx *SQLiteTx) FindActorByActorID(ctx context.Context, actorID string) (*domain.Actor, error) {
	var actor domain.Actor
	query := `SELECT id, actor_id, is_fireproof, created_at, updated_at FROM actors WHERE actor_id = ?`
	err := tx.tx.GetContext(ctx, &actor, query, actorID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find actor by actor_id %s: %w", actorID, err)
	}
	return &actor, nil
}

func (tx *SQLiteTx) ActorExists(ctx context.Context, actorID string) (bool, error) {
	var exists int
	query := `SELECT 1 FROM actors WHERE actor_id = ?`
	err := tx.tx.GetContext(ctx, &exists, query, actorID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("failed to check for existing actor ID: %w", err)
	}
	return exists == 1, nil
}

func (tx *SQLiteTx) UpdateActorID(ctx context.Context, oldActorID, newActorID string) (int64, error) {
	query := `UPDATE actors SET actor_id = ?, updated_at = CURRENT_TIMESTAMP WHERE actor_id = ?`
	result, err := tx.tx.ExecContext(ctx, query, newActorID, oldActorID)
	if err != nil {
		return 0, fmt.Errorf("failed to update actor ID: %w", err)
	}
	return result.RowsAffected()
}

func (tx *SQLiteTx) findPublicKeyByID(ctx context.Context, id int64) (*domain.PublicKey, error) {
	var key domain.PublicKey
	query := `SELECT id, actor_id, key_id, public_key, created_at, merkle_root, revoked_at, revoke_root FROM public_keys WHERE id = ?`
	err := tx.tx.GetContext(ctx, &key, query, id)
	if err != nil {
		return nil, fmt.Errorf("failed to find key by id %d: %w", id, err)
	}
	return &key, nil
}

func (tx *SQLiteTx) InsertPublicKey(ctx context.Context, key *domain.PublicKey) (*domain.PublicKey, error) {
	query := `INSERT INTO public_keys (actor_id, key_id, public_key, merkle_root) VALUES (?, ?, ?, ?)`
	result, err := tx.tx.ExecContext(ctx, query, key.ActorID, key.KeyID, key.PublicKey, key.MerkleRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to insert new public key: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert ID for key: %w", err)
	}
	return tx.findPublicKeyByID(ctx, id)
}

func (tx *SQLiteTx) FindKeyToRevoke(ctx context.Context, actorID, publicKey string) (*domain.PublicKey, error) {
	var keyToRevoke domain.PublicKey
	query := `
		SELECT pk.id FROM public_keys pk
		JOIN actors a ON pk.actor_id = a.id
		WHERE a.actor_id = ? AND pk.public_key = ? AND pk.revoked_at IS NULL`
	err := tx.tx.GetContext(ctx, &keyToRevoke, query, actorID, publicKey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find key to revoke: %w", err)
	}
	return &keyToRevoke, nil
}

func (tx *SQLiteTx) RevokeKey(ctx context.Context, keyID int64, revokeRoot string) error {
	query := `UPDATE public_keys SET revoked_at = CURRENT_TIMESTAMP, revoke_root = ? WHERE id = ?`
	_, err := tx.tx.ExecContext(ctx, query, revokeRoot, keyID)
	return err
}

func (tx *SQLiteTx) GetMessageHashesForActor(ctx context.Context, actorID int64) ([]string, error) {
	var messageHashes []string
	query := `
		SELECT merkle_root FROM public_keys WHERE actor_id = ?
		UNION
		SELECT revoke_root FROM public_keys WHERE actor_id = ? AND revoke_root IS NOT NULL`
	err := tx.tx.SelectContext(ctx, &messageHashes, query, actorID, actorID)
	if err != nil {
		return nil, fmt.Errorf("failed to gather message hashes: %w", err)
	}
	return messageHashes, nil
}

func (tx *SQLiteTx) RevokeAllKeysForActor(ctx context.Context, actorID int64, merkleRoot string) error {
	query := `UPDATE public_keys SET revoked_at = CURRENT_TIMESTAMP, revoke_root = ? WHERE actor_id = ? AND revoked_at IS NULL`
	_, err := tx.tx.ExecContext(ctx, query, merkleRoot, actorID)
	return err
}

func (tx *SQLiteTx) findAuxDataByID(ctx context.Context, id int64) (*domain.AuxiliaryData, error) {
	var aux domain.AuxiliaryData
	query := `SELECT id, actor_id, aux_id, aux_type, aux_data, created_at, merkle_root, revoked_at, revoke_root FROM auxiliary_data WHERE id = ?`
	err := tx.tx.GetContext(ctx, &aux, query, id)
	if err != nil {
		return nil, fmt.Errorf("failed to find aux data by id %d: %w", id, err)
	}
	return &aux, nil
}

func (tx *SQLiteTx) InsertAuxData(ctx context.Context, aux *domain.AuxiliaryData) (*domain.AuxiliaryData, error) {
	query := `INSERT INTO auxiliary_data (actor_id, aux_id, aux_type, aux_data, merkle_root) VALUES (?, ?, ?, ?, ?)`
	result, err := tx.tx.ExecContext(ctx, query, aux.ActorID, aux.AuxID, aux.AuxType, aux.AuxData, aux.MerkleRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to insert new auxiliary data: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert ID for aux data: %w", err)
	}
	return tx.findAuxDataByID(ctx, id)
}

func (tx *SQLiteTx) RevokeAuxData(ctx context.Context, actorID, auxID, revokeRoot string) (int64, error) {
	query := `
		UPDATE auxiliary_data
		SET revoked_at = CURRENT_TIMESTAMP, revoke_root = ?
		WHERE aux_id = ? AND actor_id = (SELECT id FROM actors WHERE actor_id = ?)`
	result, err := tx.tx.ExecContext(ctx, query, revokeRoot, auxID, actorID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (tx *SQLiteTx) StoreSymmetricKeys(ctx context.Context, messageHash string, keys map[string][]byte) (err error) {
	stmt, err := tx.tx.PreparexContext(ctx, `INSERT INTO symmetric_keys (message_hash, attribute, key) VALUES (?, ?, ?)`)
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

func (tx *SQLiteTx) DeleteSymmetricKeysByHashes(ctx context.Context, hashes []string) error {
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
