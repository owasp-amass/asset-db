-- +migrate Up

CREATE TABLE IF NOT EXISTS entities(
    entity_id INT GENERATED ALWAYS AS IDENTITY,
    created_at TIMESTAMP without time zone DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP without time zone DEFAULT CURRENT_TIMESTAMP,
    etype VARCHAR(255),
    content JSONB,
    PRIMARY KEY(entity_id)
);

CREATE INDEX idx_entities_last_seen ON entities (last_seen);
CREATE INDEX idx_entities_etype ON entities (etype);

CREATE TABLE IF NOT EXISTS entity_tags(
    tag_id INT GENERATED ALWAYS AS IDENTITY,
    created_at TIMESTAMP without time zone DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP without time zone DEFAULT CURRENT_TIMESTAMP,
    ttype VARCHAR(255),
    content JSONB,
    entity_id INT,
    PRIMARY KEY(tag_id),
    CONSTRAINT fk_entity_tags_entities
        FOREIGN KEY(entity_id)
            REFERENCES entities(entity_id)
            ON DELETE CASCADE
);

CREATE INDEX idx_enttag_last_seen ON entity_tags (last_seen);
CREATE INDEX idx_enttag_ttype ON entity_tags (ttype);
CREATE INDEX idx_enttag_entity_id ON entity_tags (entity_id);

CREATE TABLE IF NOT EXISTS edges(
    edge_id INT GENERATED ALWAYS AS IDENTITY,
    created_at TIMESTAMP without time zone DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP without time zone DEFAULT CURRENT_TIMESTAMP,
    etype VARCHAR(255),
    content JSONB,
    from_entity_id INT,
    to_entity_id INT,
    PRIMARY KEY(edge_id),
    CONSTRAINT fk_edges_entities_from
        FOREIGN KEY(from_entity_id)
            REFERENCES entities(entity_id)
            ON DELETE CASCADE,
    CONSTRAINT fk_edges_entities_to
        FOREIGN KEY(to_entity_id)
            REFERENCES entities(entity_id)
            ON DELETE CASCADE
);

CREATE INDEX idx_edge_last_seen ON edges (last_seen);
CREATE INDEX idx_edge_etype ON edges (etype);
CREATE INDEX idx_edge_from_entity_id ON edges (from_entity_id);
CREATE INDEX idx_edge_to_entity_id ON edges (to_entity_id);

CREATE TABLE IF NOT EXISTS edge_tags(
    tag_id INT GENERATED ALWAYS AS IDENTITY,
    created_at TIMESTAMP without time zone DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP without time zone DEFAULT CURRENT_TIMESTAMP,
    ttype VARCHAR(255),
    content JSONB,
    edge_id INT,
    PRIMARY KEY(tag_id),
    CONSTRAINT fk_edge_tags_edges
        FOREIGN KEY(edge_id)
            REFERENCES edges(edge_id)
            ON DELETE CASCADE
);

CREATE INDEX idx_edgetag_last_seen ON edge_tags (last_seen);
CREATE INDEX idx_edgetag_ttype ON edge_tags (ttype);
CREATE INDEX idx_edgetag_edge_id ON edge_tags (edge_id);

-- +migrate Down

DROP INDEX IF EXISTS idx_edgetag_edge_id;
DROP INDEX IF EXISTS idx_edgetag_ttype;
DROP INDEX IF EXISTS idx_edgetag_last_seen;
DROP TABLE edge_tags;

DROP INDEX IF EXISTS idx_edge_to_entity_id;
DROP INDEX IF EXISTS idx_edge_from_entity_id;
DROP INDEX IF EXISTS idx_edge_etype;
DROP INDEX IF EXISTS idx_edge_last_seen;
DROP TABLE edges;

DROP INDEX IF EXISTS idx_enttag_entity_id;
DROP INDEX IF EXISTS idx_enttag_ttype;
DROP INDEX IF EXISTS idx_enttag_last_seen;
DROP TABLE entity_tags;

DROP INDEX IF EXISTS idx_entities_etype;
DROP INDEX IF EXISTS idx_entities_last_seen;
DROP TABLE entities;
