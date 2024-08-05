-- +migrate Up
CREATE INDEX IF NOT EXISTS idx_rel_type ON relations (type);

-- +migrate Down
DROP INDEX IF EXISTS idx_rel_type;