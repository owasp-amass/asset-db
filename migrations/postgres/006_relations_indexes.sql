-- +migrate Up

CREATE INDEX idx_rel_created_at ON relations (created_at);
CREATE INDEX idx_rel_last_seen ON assets (last_seen);

-- +migrate Down

DROP INDEX idx_rel_created_at;
DROP INDEX idx_rel_last_seen;