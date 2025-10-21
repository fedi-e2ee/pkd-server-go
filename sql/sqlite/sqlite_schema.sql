-- Actors table stores information about each user/entity.
CREATE TABLE actors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id TEXT UNIQUE NOT NULL,
    is_fireproof INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_actors_actor_id ON actors(actor_id);

-- PublicKeys table stores public keys associated with actors.
CREATE TABLE public_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    key_id TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at DATETIME,
    revoke_root TEXT
);
CREATE INDEX idx_public_keys_actor_id ON public_keys(actor_id);
CREATE INDEX idx_public_keys_key_id ON public_keys(key_id);

-- AuxiliaryData table stores other data associated with actors.
CREATE TABLE auxiliary_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    aux_id TEXT UNIQUE NOT NULL,
    aux_type TEXT NOT NULL,
    aux_data TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at DATETIME,
    revoke_root TEXT
);
CREATE INDEX idx_auxiliary_data_actor_id ON auxiliary_data(actor_id);
CREATE INDEX idx_auxiliary_data_aux_id ON auxiliary_data(aux_id);

-- SymmetricKeys table stores the keys for crypto-shredding.
CREATE TABLE symmetric_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_hash TEXT NOT NULL,
    attribute TEXT NOT NULL,
    key BLOB NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(message_hash, attribute)
);
CREATE INDEX idx_symmetric_keys_message_hash ON symmetric_keys(message_hash);

-- MessageLog stores the history of all processed protocol messages.
CREATE TABLE message_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_hash TEXT UNIQUE NOT NULL,
    encrypted_message BLOB NOT NULL,
    decrypted_message TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_message_logs_message_hash ON message_logs(message_hash);

-- TOTPSecrets stores TOTP secrets for Fediverse instances.
CREATE TABLE totp_secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance TEXT UNIQUE NOT NULL,
    encrypted_secret BLOB NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_totp_secrets_instance ON totp_secrets(instance);

-- TlogEntries table stores the entries for the transparency log.
CREATE TABLE tlog_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    merkle_root BLOB NOT NULL,
    signed_message BLOB NOT NULL,
    public_key_hash BLOB NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_tlog_entries_merkle_root ON tlog_entries(merkle_root);
