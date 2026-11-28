-- +migrate Up

-- ============================================================================
-- OWASP Amass: the deletion count (repository.ChangeReader)
--
-- A reader that keeps what it read asks which entities changed since its
-- last read, by their updated_at times. A deleted row leaves no time, so
-- every deletion of an entity, an edge or a tag also adds one here, in the
-- same transaction; a reader that sees the count move starts over.
-- ============================================================================

CREATE TABLE IF NOT EXISTS graph_change (
  id        INTEGER PRIMARY KEY CHECK (id = 1),
  deletions INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO graph_change (id) VALUES (1);

-- +migrate Down

DROP TABLE IF EXISTS graph_change;
