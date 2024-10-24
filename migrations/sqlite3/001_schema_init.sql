-- +migrate Up

-- see https://www.sqlite.org/foreignkeys.html#fk_enable about enabling foreign keys
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS entities(
    entity_id INTEGER PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    etype TEXT,
    content TEXT,
);

CREATE INDEX idx_entities_last_seen ON entities (last_seen);
CREATE INDEX idx_entities_etype ON entities (etype);

CREATE TABLE IF NOT EXISTS entity_properties(
    property_id INTEGER PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    ptype TEXT,
    content TEXT,
    entity_id INTEGER,
    FOREIGN KEY(entity_id)
        REFERENCES entities(entity_id)
        ON DELETE CASCADE
);

CREATE INDEX idx_entprop_last_seen ON entity_properties (last_seen);
CREATE INDEX idx_entprop_ptype ON entity_properties (ptype);
CREATE INDEX idx_entprop_entity_id ON entity_properties (entity_id);

CREATE TABLE IF NOT EXISTS relations(
    relation_id INTEGER PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    rtype TEXT,
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

CREATE INDEX idx_rel_last_seen ON relations (last_seen);
CREATE INDEX idx_rel_rtype ON relations (rtype);
CREATE INDEX idx_rel_from_entity_id ON relations (from_entity_id);
CREATE INDEX idx_rel_to_entity_id ON relations (to_entity_id);

CREATE TABLE IF NOT EXISTS relation_properties(
    property_id INTEGER PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    ptype TEXT,
    content TEXT,
    relation_id INTEGER,
    FOREIGN KEY(relation_id)
        REFERENCES relations(relation_id)
        ON DELETE CASCADE
);

CREATE INDEX idx_relprop_last_seen ON relation_properties (last_seen);
CREATE INDEX idx_relprop_ptype ON relation_properties (ptype);
CREATE INDEX idx_relprop_relation_id ON relation_properties (relation_id);

-- +migrate Down

DROP INDEX IF EXISTS idx_relprop_relation_id;
DROP INDEX IF EXISTS idx_relprop_ptype;
DROP INDEX IF EXISTS idx_relprop_last_seen;
DROP TABLE relation_properties;

DROP INDEX IF EXISTS idx_rel_to_entity_id;
DROP INDEX IF EXISTS idx_rel_from_entity_id;
DROP INDEX IF EXISTS idx_rel_rtype;
DROP INDEX IF EXISTS idx_rel_last_seen;
DROP TABLE relations;

DROP INDEX IF EXISTS idx_entprop_entity_id;
DROP INDEX IF EXISTS idx_entprop_ptype;
DROP INDEX IF EXISTS idx_entprop_last_seen;
DROP TABLE entity_properties;

DROP INDEX IF EXISTS idx_entities_etype;
DROP INDEX IF EXISTS idx_entities_last_seen;
DROP TABLE entities;
