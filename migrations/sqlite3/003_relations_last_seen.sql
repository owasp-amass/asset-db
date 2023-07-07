-- +migrate Up

ALTER TABLE relations ADD COLUMN last_seen DATETIME DEFAULT CURRENT_TIMESTAMP;

-- +migrate Down

ALTER TABLE relations DROP COLUMN last_seen;
