-- +migrate Up

-- ============================================================================
-- OWASP Amass: secrets (SQLite)
--
-- Credentials the tools sharing the database keep in it, such as data
-- source API keys (repository.SecretStore). Only what the tools encrypted is
-- stored: the ciphertext, its nonce and the ID of the key; the tools hold
-- the key. Times are UTC text, as elsewhere in this schema.
-- ============================================================================

CREATE TABLE IF NOT EXISTS secret (
  name        TEXT PRIMARY KEY,
  ciphertext  BLOB NOT NULL,
  nonce       BLOB NOT NULL,
  key_id      TEXT NOT NULL,
  updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_by  TEXT NOT NULL DEFAULT ''
);

-- +migrate Down

DROP TABLE IF EXISTS secret;
