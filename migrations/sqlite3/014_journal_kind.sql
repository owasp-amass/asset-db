-- +migrate Up

-- ============================================================================
-- OWASP Amass: journal records by kind (SQLite)
--
-- A reader may ask for some kinds of a topic's records only
-- (repository.JournalStore ReadJournalFiltered), such as the job records
-- among a topic that also holds every job's per-asset records; this index
-- serves those reads.
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_journal_topic_kind ON journal (topic, kind, seq);

-- +migrate Down

DROP INDEX IF EXISTS idx_journal_topic_kind;
