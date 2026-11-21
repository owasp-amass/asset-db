-- +migrate Up

-- ============================================================================
-- OWASP Amass: StorageBucket table native for asset type (SQLite)
--
-- An object-storage bucket (Amazon S3, Google Cloud Storage, Azure Blob),
-- identified by "<service>:<bucket>" within its provider's global namespace.
-- bucket_exists and is_public hold the latest observation, so a later
-- sighting replaces them rather than merging.
-- ============================================================================

INSERT OR IGNORE INTO entity_type_lu(name) VALUES ('storagebucket');

CREATE TABLE IF NOT EXISTS storagebucket (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  unique_id     TEXT NOT NULL UNIQUE,
  bucket_name   TEXT NOT NULL,
  provider      TEXT,
  service       TEXT,
  bucket_exists INTEGER NOT NULL DEFAULT 0,
  is_public     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_storagebucket_updated_at ON storagebucket (updated_at);
CREATE INDEX IF NOT EXISTS idx_storagebucket_bucket_name ON storagebucket (bucket_name);
CREATE INDEX IF NOT EXISTS idx_storagebucket_provider ON storagebucket (provider);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_storagebucket_ai
AFTER INSERT ON storagebucket
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='storagebucket' LIMIT 1), NEW.unique_id, 'storagebucket', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_storagebucket_au
AFTER UPDATE ON storagebucket
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='storagebucket' LIMIT 1), NEW.unique_id, 'storagebucket', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate Down

DROP TRIGGER IF EXISTS trg_storagebucket_au;
DROP TRIGGER IF EXISTS trg_storagebucket_ai;
DROP INDEX IF EXISTS idx_storagebucket_provider;
DROP INDEX IF EXISTS idx_storagebucket_bucket_name;
DROP INDEX IF EXISTS idx_storagebucket_updated_at;
DROP TABLE IF EXISTS storagebucket;
DELETE FROM entity_type_lu WHERE name = 'storagebucket';
