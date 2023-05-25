-- +migrate Up

-- see https://www.sqlite.org/foreignkeys.html#fk_enable about enabling foreign keys
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS assets(
    id INTEGER PRIMARY KEY,
    created_at DATETIME,
    type TEXT,
    content TEXT);

CREATE TABLE IF NOT EXISTS relations(
    id INTEGER PRIMARY KEY,
    created_at DATETIME,
    type TEXT,
    from_asset_id INTEGER,
    to_asset_id INTEGER,
    FOREIGN KEY(from_asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY(to_asset_id) REFERENCES assets(id) ON DELETE CASCADE);

-- +migrate Down

DROP TABLE relations;
DROP TABLE assets;
