-- +migrate Up

CREATE TABLE IF NOT EXISTS assets(
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    type VARCHAR(255),
    content JSONB);

CREATE TABLE IF NOT EXISTS relations(
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    type VARCHAR(255),
    from_asset_id INT,
    to_asset_id INT,
    CONSTRAINT fk_from_asset
        FOREIGN KEY (from_asset_id)
        REFERENCES assets(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_to_asset
        FOREIGN KEY (to_asset_id)
        REFERENCES assets(id)
        ON DELETE CASCADE);

-- +migrate Down

DROP TABLE relations;
DROP TABLE assets;
