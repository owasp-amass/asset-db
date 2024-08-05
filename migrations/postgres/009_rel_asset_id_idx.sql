-- +migrate Up
CREATE INDEX IF NOT EXISTS idx_rel_from_asset ON relations (from_asset_id);
CREATE INDEX IF NOT EXISTS idx_rel_to_asset ON relations (to_asset_id);

-- +migrate Down
DROP INDEX IF EXISTS idx_rel_from_asset;
DROP INDEX IF EXISTS idx_rel_to_asset;