-- +migrate Up

-- ============================================================================
-- OWASP Amass: collection runs (SQLite)
--
-- One row per run of a tool that collected data into the database: an
-- Amass enumeration, an import, a scanner. Any tool may record its runs
-- (repository.RunRecorder), with what it was asked to collect (scope: Open
-- Asset Model asset types and keys), when it started and finished, and how
-- it ended. Times are UTC text, as elsewhere in this schema.
-- ============================================================================

CREATE TABLE IF NOT EXISTS collection_run (
  run_id       TEXT PRIMARY KEY,
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  tool         TEXT NOT NULL,
  tool_version TEXT NOT NULL DEFAULT '',
  external_id  TEXT NOT NULL DEFAULT '',
  status       TEXT NOT NULL CHECK (status IN ('running', 'finished', 'stopped', 'failed')),
  started_at   TEXT NOT NULL,
  finished_at  TEXT,
  scope        TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(scope)),
  metadata     TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata))
);
CREATE INDEX IF NOT EXISTS idx_collection_run_started_at ON collection_run (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_collection_run_tool ON collection_run (tool, started_at DESC);

-- +migrate Down

DROP INDEX IF EXISTS idx_collection_run_tool;
DROP INDEX IF EXISTS idx_collection_run_started_at;
DROP TABLE IF EXISTS collection_run;
