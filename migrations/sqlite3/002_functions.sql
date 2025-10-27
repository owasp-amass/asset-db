-- +migrate Up

PRAGMA foreign_keys = ON;

-- Holds reusable, named SQL templates (CTEs for upserts, edge/tag helpers, etc.)
CREATE TABLE IF NOT EXISTS sql_templates (
  name TEXT PRIMARY KEY,
  sql  TEXT NOT NULL,                 -- the exact SQL to Prepare (WITH ... SELECT ...)
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
CREATE INDEX IF NOT EXISTS idx_sql_templates_updated_at ON sql_templates(updated_at);

-- Optional: versioning for migrations (for your own pipeline)
CREATE TABLE IF NOT EXISTS migration_meta (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  tag TEXT NOT NULL,
  notes TEXT
);
-- Mark this migration
INSERT INTO migration_meta(tag, notes) VALUES ('install-sql-templates', 'Catalog table + helper views created');

-- +migrate Down

DROP TABLE IF EXISTS migration_meta;
DROP INDEX IF EXISTS idx_sql_templates_updated_at;
DROP TABLE IF EXISTS sql_templates;