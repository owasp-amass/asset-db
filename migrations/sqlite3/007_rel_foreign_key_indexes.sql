-- +migrate Up

CREATE INDEX idx_rel_from_asset_id ON relations (from_asset_id);
CREATE INDEX idx_rel_to_asset_id ON relations (to_asset_id);

-- +migrate Down

DROP INDEX idx_rel_from_asset_id;
DROP INDEX idx_rel_to_asset_id;