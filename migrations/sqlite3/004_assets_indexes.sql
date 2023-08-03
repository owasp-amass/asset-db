-- +migrate Up

-- Index the `name` field of the `content` jsonb when type is `FQDN`
-- Assumes the pg_trgm extension is created in the database
CREATE INDEX fqdn_name ON assets (content->>'name' COLLATE NOCASE) WHERE type = 'FQDN';

-- Index assets.type
CREATE INDEX idx_assets_type ON assets (type);

-- Index created_at
CREATE INDEX idx_as_created_at ON assets (created_at);

-- Index last_seen
CREATE INDEX idx_as_last_seen ON assets (last_seen);


-- +migrate Down

-- drop all the indexes we just created
DROP INDEX idx_fqdn_content_name;
DROP INDEX idx_assets_type_hash;
DROP INDEX idx_as_created_at;
DROP INDEX idx_as_last_seen;