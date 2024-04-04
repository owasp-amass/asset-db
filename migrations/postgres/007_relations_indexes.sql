-- +migrate Up

DROP INDEX IF EXISTS idx_rel_last_seen;
CREATE INDEX idx_rel_last_seen ON relations (last_seen);

-- +migrate Down

DROP INDEX IF EXISTS idx_rel_last_seen;