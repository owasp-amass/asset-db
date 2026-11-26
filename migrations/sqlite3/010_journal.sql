-- +migrate Up

-- ============================================================================
-- OWASP Amass: the journal and leases (SQLite)
--
-- journal: an append-only log the tools sharing the database coordinate
-- through (repository.JournalStore). Records are grouped by topic, and
-- within a topic by kind and key; their data is the tool's own JSON. seq
-- orders the records.
--
-- lease: named work that one holder at a time may do until it expires or is
-- released (repository.LeaseStore). Times are UTC text, as elsewhere in this
-- schema.
-- ============================================================================

CREATE TABLE IF NOT EXISTS journal (
  seq    INTEGER PRIMARY KEY AUTOINCREMENT,
  topic  TEXT NOT NULL,
  kind   TEXT NOT NULL,
  key    TEXT NOT NULL DEFAULT '',
  data   TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(data)),
  actor  TEXT NOT NULL DEFAULT '',
  at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  cause  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_journal_topic_seq ON journal (topic, seq);
CREATE INDEX IF NOT EXISTS idx_journal_topic_key ON journal (topic, key, seq);

CREATE TABLE IF NOT EXISTS lease (
  name        TEXT PRIMARY KEY,
  holder      TEXT NOT NULL,
  acquired_at TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  data        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(data))
);

-- +migrate Down

DROP TABLE IF EXISTS lease;
DROP INDEX IF EXISTS idx_journal_topic_key;
DROP INDEX IF EXISTS idx_journal_topic_seq;
DROP TABLE IF EXISTS journal;
