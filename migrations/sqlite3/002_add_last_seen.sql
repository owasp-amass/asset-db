-- +migrate Up

ALTER TABLE assets ADD COLUMN last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- +migrate Down

ALTER TABLE assets DROP COLUMN last_seen;
