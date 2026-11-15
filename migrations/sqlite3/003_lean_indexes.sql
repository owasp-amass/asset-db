-- +migrate Up

-- ============================================================================
-- OWASP Amass: leaner indexes and edge identity (SQLite)
--
-- * Indexes no query uses, or that another index covers, are dropped.
-- * Edges are found through (entity, label) indexes.
-- * A source tag is one row per source: its confidence is kept in the
--   content, which the latest sighting updates; duplicates are merged.
-- * DNS edges are distinct per record type: the edge table is rebuilt with
--   rr_type, a generated column, in its identity (edge_tag is copied with it,
--   keeping every edge and tag id).
-- No table, column or data type of the Open Asset Model changes.
-- ============================================================================

DROP INDEX IF EXISTS idx_entity_created_at;
DROP INDEX IF EXISTS idx_entity_updated_at;
DROP INDEX IF EXISTS idx_entity_tag_created_at;
DROP INDEX IF EXISTS idx_entity_tag_updated_at;
DROP INDEX IF EXISTS idx_entity_tag_entity_updated;
DROP INDEX IF EXISTS idx_entity_tag_entity_id;
DROP INDEX IF EXISTS idx_entity_tag_ttype_id;
DROP INDEX IF EXISTS idx_entity_tag_property_name;
DROP INDEX IF EXISTS idx_entity_tag_tt_name;
DROP INDEX IF EXISTS idx_entity_tag_ttype_name_value;
DROP INDEX IF EXISTS idx_edge_tag_created_at;
DROP INDEX IF EXISTS idx_edge_tag_updated_at;
DROP INDEX IF EXISTS idx_edge_tag_edge_updated;
DROP INDEX IF EXISTS idx_edge_tag_edge_id;
DROP INDEX IF EXISTS idx_edge_tag_ttype_id;
DROP INDEX IF EXISTS idx_edge_tag_property_name;
DROP INDEX IF EXISTS idx_edge_tag_tt_name;
DROP INDEX IF EXISTS idx_edge_tag_property_name_value;
DROP INDEX IF EXISTS idx_edge_tag_ttype_name_value;
DROP INDEX IF EXISTS idx_account_created_at;
DROP INDEX IF EXISTS idx_autnumrecord_created_at;
DROP INDEX IF EXISTS idx_autonomoussystem_created_at;
DROP INDEX IF EXISTS idx_contactrecord_created_at;
DROP INDEX IF EXISTS idx_domainrecord_created_at;
DROP INDEX IF EXISTS idx_file_created_at;
DROP INDEX IF EXISTS idx_fqdn_created_at;
DROP INDEX IF EXISTS idx_fundstransfer_created_at;
DROP INDEX IF EXISTS idx_identifier_created_at;
DROP INDEX IF EXISTS idx_ipaddress_created_at;
DROP INDEX IF EXISTS idx_ipnetrecord_created_at;
DROP INDEX IF EXISTS idx_location_created_at;
DROP INDEX IF EXISTS idx_netblock_created_at;
DROP INDEX IF EXISTS idx_organization_created_at;
DROP INDEX IF EXISTS idx_person_created_at;
DROP INDEX IF EXISTS idx_phone_created_at;
DROP INDEX IF EXISTS idx_product_created_at;
DROP INDEX IF EXISTS idx_productrelease_created_at;
DROP INDEX IF EXISTS idx_service_created_at;
DROP INDEX IF EXISTS idx_tlscertificate_created_at;
DROP INDEX IF EXISTS idx_url_created_at;

-- One source tag per source: keep the latest, first seen at the earliest.
UPDATE entity_tag SET created_at = (
    SELECT min(o.created_at) FROM entity_tag o
    WHERE o.entity_id = entity_tag.entity_id AND o.ttype_id = entity_tag.ttype_id
      AND o.property_name = entity_tag.property_name)
WHERE ttype_id = (SELECT id FROM tag_type_lu WHERE name = 'sourceproperty');
DELETE FROM entity_tag WHERE tag_id IN (
    SELECT tag_id FROM (
        SELECT tag_id, row_number() OVER (PARTITION BY entity_id, property_name
                                          ORDER BY updated_at DESC, tag_id DESC) AS rn
        FROM entity_tag WHERE ttype_id = (SELECT id FROM tag_type_lu WHERE name = 'sourceproperty'))
    WHERE rn > 1);
UPDATE entity_tag SET property_value = ''
WHERE ttype_id = (SELECT id FROM tag_type_lu WHERE name = 'sourceproperty');

UPDATE edge_tag SET created_at = (
    SELECT min(o.created_at) FROM edge_tag o
    WHERE o.edge_id = edge_tag.edge_id AND o.ttype_id = edge_tag.ttype_id
      AND o.property_name = edge_tag.property_name)
WHERE ttype_id = (SELECT id FROM tag_type_lu WHERE name = 'sourceproperty');
DELETE FROM edge_tag WHERE tag_id IN (
    SELECT tag_id FROM (
        SELECT tag_id, row_number() OVER (PARTITION BY edge_id, property_name
                                          ORDER BY updated_at DESC, tag_id DESC) AS rn
        FROM edge_tag WHERE ttype_id = (SELECT id FROM tag_type_lu WHERE name = 'sourceproperty'))
    WHERE rn > 1);
UPDATE edge_tag SET property_value = ''
WHERE ttype_id = (SELECT id FROM tag_type_lu WHERE name = 'sourceproperty');

-- Rebuild the edge table with the record type in its identity, and edge_tag
-- with it: SQLite repoints references to a renamed table, so the tables are
-- copied whole and the copies renamed into place.
DROP INDEX IF EXISTS idx_edge_created_at;
DROP INDEX IF EXISTS idx_edge_updated_at;
DROP INDEX IF EXISTS idx_edge_etype_id;
DROP INDEX IF EXISTS idx_edge_from_id;
DROP INDEX IF EXISTS idx_edge_to_id;
DROP INDEX IF EXISTS idx_edge_from;
DROP INDEX IF EXISTS idx_edge_to;
DROP TRIGGER IF EXISTS trg_edge_au;
CREATE TABLE edge_new (
  edge_id        INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  etype_id       INTEGER NOT NULL REFERENCES edge_type_lu(id),
  label          TEXT COLLATE NOCASE NOT NULL,
  content        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(content)),
  from_entity_id INTEGER NOT NULL REFERENCES entity(entity_id) ON DELETE CASCADE,
  to_entity_id   INTEGER NOT NULL REFERENCES entity(entity_id) ON DELETE CASCADE,
  rr_type        TEXT GENERATED ALWAYS AS
                   (CAST(coalesce(json_extract(content, '$.header.rr_type'), '') AS TEXT)) VIRTUAL,
  CHECK (from_entity_id <> to_entity_id)
);

INSERT INTO edge_new (edge_id, created_at, updated_at, etype_id, label, content, from_entity_id, to_entity_id)
SELECT edge_id, created_at, updated_at, etype_id, label, content, from_entity_id, to_entity_id FROM edge;

CREATE TABLE edge_tag_new (
  tag_id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  edge_id        INTEGER NOT NULL REFERENCES edge_new(edge_id) ON DELETE CASCADE,
  ttype_id       INTEGER NOT NULL REFERENCES tag_type_lu(id),
  property_name  TEXT NOT NULL,
  property_value TEXT NOT NULL,
  content        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(content)),
  UNIQUE (edge_id, ttype_id, property_name, property_value)
);

INSERT INTO edge_tag_new (tag_id, created_at, updated_at, edge_id, ttype_id, property_name, property_value, content)
SELECT tag_id, created_at, updated_at, edge_id, ttype_id, property_name, property_value, content FROM edge_tag
WHERE edge_id IN (SELECT edge_id FROM edge_new);

-- nothing references the old tables now, so dropping them deletes nothing else
DROP TABLE edge_tag;
DROP TABLE edge;
-- renaming edge_new repoints edge_tag_new at it
ALTER TABLE edge_new RENAME TO edge;
ALTER TABLE edge_tag_new RENAME TO edge_tag;
DELETE FROM sqlite_sequence WHERE name IN ('edge', 'edge_tag');
INSERT INTO sqlite_sequence (name, seq) SELECT 'edge', coalesce(max(edge_id), 0) FROM edge;
INSERT INTO sqlite_sequence (name, seq) SELECT 'edge_tag', coalesce(max(tag_id), 0) FROM edge_tag;

CREATE UNIQUE INDEX edge_identity_uidx ON edge (from_entity_id, label, etype_id, to_entity_id, rr_type);
CREATE INDEX edge_to_label_idx ON edge (to_entity_id, label);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_edge_au
AFTER UPDATE OF content ON edge
BEGIN
  UPDATE edge SET updated_at = CURRENT_TIMESTAMP WHERE edge_id = NEW.edge_id;
END;
-- +migrate StatementEnd

-- +migrate Down

-- The edge table returns to one edge per type, label and endpoints: of the
-- DNS edges that differ only in record type, the latest is kept with its tags.
DROP INDEX IF EXISTS edge_identity_uidx;
DROP INDEX IF EXISTS edge_to_label_idx;
DROP TRIGGER IF EXISTS trg_edge_au;
CREATE TABLE edge_new (
  edge_id        INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  etype_id       INTEGER NOT NULL REFERENCES edge_type_lu(id),
  label          TEXT COLLATE NOCASE NOT NULL,
  content        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(content)),
  from_entity_id INTEGER NOT NULL REFERENCES entity(entity_id) ON DELETE CASCADE,
  to_entity_id   INTEGER NOT NULL REFERENCES entity(entity_id) ON DELETE CASCADE,
  UNIQUE (etype_id, from_entity_id, to_entity_id, label),
  CHECK (from_entity_id <> to_entity_id)
);

INSERT INTO edge_new (edge_id, created_at, updated_at, etype_id, label, content, from_entity_id, to_entity_id)
SELECT edge_id, created_at, updated_at, etype_id, label, content, from_entity_id, to_entity_id FROM (
    SELECT *, row_number() OVER (PARTITION BY etype_id, from_entity_id, to_entity_id, label
                                 ORDER BY updated_at DESC, edge_id DESC) AS rn
    FROM edge)
WHERE rn = 1;

CREATE TABLE edge_tag_new (
  tag_id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  edge_id        INTEGER NOT NULL REFERENCES edge_new(edge_id) ON DELETE CASCADE,
  ttype_id       INTEGER NOT NULL REFERENCES tag_type_lu(id),
  property_name  TEXT NOT NULL,
  property_value TEXT NOT NULL,
  content        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(content)),
  UNIQUE (edge_id, ttype_id, property_name, property_value)
);

INSERT INTO edge_tag_new (tag_id, created_at, updated_at, edge_id, ttype_id, property_name, property_value, content)
SELECT tag_id, created_at, updated_at, edge_id, ttype_id, property_name, property_value, content FROM edge_tag
WHERE edge_id IN (SELECT edge_id FROM edge_new);

-- nothing references the old tables now, so dropping them deletes nothing else
DROP TABLE edge_tag;
DROP TABLE edge;
-- renaming edge_new repoints edge_tag_new at it
ALTER TABLE edge_new RENAME TO edge;
ALTER TABLE edge_tag_new RENAME TO edge_tag;
DELETE FROM sqlite_sequence WHERE name IN ('edge', 'edge_tag');
INSERT INTO sqlite_sequence (name, seq) SELECT 'edge', coalesce(max(edge_id), 0) FROM edge;
INSERT INTO sqlite_sequence (name, seq) SELECT 'edge_tag', coalesce(max(tag_id), 0) FROM edge_tag;

CREATE INDEX IF NOT EXISTS idx_edge_created_at ON edge (created_at);
CREATE INDEX IF NOT EXISTS idx_edge_updated_at ON edge (updated_at);
CREATE INDEX IF NOT EXISTS idx_edge_etype_id ON edge (etype_id);
CREATE INDEX IF NOT EXISTS idx_edge_from_id ON edge (from_entity_id);
CREATE INDEX IF NOT EXISTS idx_edge_to_id   ON edge (to_entity_id);
CREATE INDEX IF NOT EXISTS idx_edge_from ON edge (from_entity_id, etype_id, to_entity_id);
CREATE INDEX IF NOT EXISTS idx_edge_to   ON edge (to_entity_id, etype_id, from_entity_id);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_edge_au
AFTER UPDATE OF content ON edge
BEGIN
  UPDATE edge SET updated_at = CURRENT_TIMESTAMP WHERE edge_id = NEW.edge_id;
END;
-- +migrate StatementEnd

-- Source tags hold their confidence again; duplicates merged by Up stay merged.
UPDATE entity_tag SET property_value = coalesce(json_extract(content, '$.confidence'), '')
WHERE ttype_id = (SELECT id FROM tag_type_lu WHERE name = 'sourceproperty');
UPDATE edge_tag SET property_value = coalesce(json_extract(content, '$.confidence'), '')
WHERE ttype_id = (SELECT id FROM tag_type_lu WHERE name = 'sourceproperty');

CREATE INDEX IF NOT EXISTS idx_entity_created_at ON entity (created_at);
CREATE INDEX IF NOT EXISTS idx_entity_updated_at ON entity (updated_at);
CREATE INDEX IF NOT EXISTS idx_entity_tag_created_at ON entity_tag (created_at);
CREATE INDEX IF NOT EXISTS idx_entity_tag_updated_at ON entity_tag (updated_at);
CREATE INDEX IF NOT EXISTS idx_entity_tag_entity_updated ON entity_tag (entity_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_entity_tag_entity_id ON entity_tag (entity_id);
CREATE INDEX IF NOT EXISTS idx_entity_tag_ttype_id ON entity_tag (ttype_id);
CREATE INDEX IF NOT EXISTS idx_entity_tag_property_name ON entity_tag (property_name);
CREATE INDEX IF NOT EXISTS idx_entity_tag_tt_name ON entity_tag (ttype_id, property_name);
CREATE INDEX IF NOT EXISTS idx_entity_tag_ttype_name_value ON entity_tag (ttype_id, property_name, property_value);
CREATE INDEX IF NOT EXISTS idx_edge_tag_created_at ON edge_tag (created_at);
CREATE INDEX IF NOT EXISTS idx_edge_tag_updated_at ON edge_tag (updated_at);
CREATE INDEX IF NOT EXISTS idx_edge_tag_edge_updated ON edge_tag (edge_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_edge_tag_edge_id ON edge_tag (edge_id);
CREATE INDEX IF NOT EXISTS idx_edge_tag_ttype_id ON edge_tag (ttype_id);
CREATE INDEX IF NOT EXISTS idx_edge_tag_property_name ON edge_tag (property_name);
CREATE INDEX IF NOT EXISTS idx_edge_tag_tt_name ON edge_tag (ttype_id, property_name);
CREATE INDEX IF NOT EXISTS idx_edge_tag_property_name_value ON edge_tag (property_name, property_value);
CREATE INDEX IF NOT EXISTS idx_edge_tag_ttype_name_value ON edge_tag (ttype_id, property_name, property_value);
