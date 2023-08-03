-- +migrate Up

-- Index the `name` field of the `content` jsonb when type is `FQDN`
-- Assumes the pg_trgm extension is created in the database
CREATE INDEX idx_fqdn_content_name ON assets USING gin ((content->>'name') gin_trgm_ops) WHERE type = 'FQDN';

-- Index assets.type
CREATE INDEX idx_assets_type_hash ON assets USING hash (type);

-- Index last_seen
CREATE INDEX idx_last_seen ON assets (last_seen);


-- +migrate Down

-- drop all the indexes we just created
DROP INDEX idx_fqdn_content_name;
DROP INDEX idx_assets_type_hash;
DROP INDEX idx_last_seen;