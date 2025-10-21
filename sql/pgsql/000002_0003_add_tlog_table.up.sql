-- TlogEntries table stores the entries for the transparency log.
CREATE TABLE tlog_entries (
    id SERIAL PRIMARY KEY,
    merkle_root BYTEA NOT NULL,
    signed_message BYTEA NOT NULL,
    public_key_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_tlog_entries_merkle_root ON tlog_entries(merkle_root);
