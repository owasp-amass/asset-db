-- +migrate Up

-- see https://www.sqlite.org/foreignkeys.html#fk_enable about enabling foreign keys
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS entities(
    entity_id INTEGER PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    etype TEXT,
    content TEXT
);

CREATE INDEX idx_entities_last_seen ON entities (last_seen);
CREATE INDEX idx_entities_etype ON entities (etype);

CREATE TABLE IF NOT EXISTS entity_tags(
    tag_id INTEGER PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    ttype TEXT,
    content TEXT,
    entity_id INTEGER,
    FOREIGN KEY(entity_id)
        REFERENCES entities(entity_id)
        ON DELETE CASCADE
);

CREATE INDEX idx_enttag_last_seen ON entity_tags (last_seen);
CREATE INDEX idx_enttag_entity_id ON entity_tags (entity_id);

CREATE TABLE IF NOT EXISTS edges(
    edge_id INTEGER PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    etype TEXT,
    content TEXT,
    from_entity_id INTEGER,
    to_entity_id INTEGER,
    FOREIGN KEY(from_entity_id) 
        REFERENCES entities(entity_id) 
        ON DELETE CASCADE,
    FOREIGN KEY(to_entity_id) 
        REFERENCES entities(entity_id) 
        ON DELETE CASCADE
);

CREATE INDEX idx_edge_last_seen ON edges (last_seen);
CREATE INDEX idx_edge_from_entity_id ON edges (from_entity_id);
CREATE INDEX idx_edge_to_entity_id ON edges (to_entity_id);

CREATE TABLE IF NOT EXISTS edge_tags(
    tag_id INTEGER PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    ttype TEXT,
    content TEXT,
    edge_id INTEGER,
    FOREIGN KEY(edge_id)
        REFERENCES edges(edge_id)
        ON DELETE CASCADE
);

CREATE INDEX idx_edgetag_last_seen ON edge_tags (last_seen);
CREATE INDEX idx_edgetag_edge_id ON edge_tags (edge_id);

-- +migrate Down

DROP INDEX IF EXISTS idx_edgetag_edge_id;
DROP INDEX IF EXISTS idx_edgetag_last_seen;
DROP TABLE edge_tags;

DROP INDEX IF EXISTS idx_edge_to_entity_id;
DROP INDEX IF EXISTS idx_edge_from_entity_id;
DROP INDEX IF EXISTS idx_edge_last_seen;
DROP TABLE edges;

DROP INDEX IF EXISTS idx_enttag_last_seen;
DROP INDEX IF EXISTS idx_entprop_last_seen;
DROP TABLE entity_tags;

DROP INDEX IF EXISTS idx_entities_etype;
DROP INDEX IF EXISTS idx_entities_last_seen;
DROP TABLE entities;
