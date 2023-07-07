-- +migrate Up

ALTER TABLE assets ADD COLUMN last_seen DATETIME DEFAULT CURRENT_TIMESTAMP;

-- +migrate Down

ALTER TABLE assets DROP COLUMN last_seen;
