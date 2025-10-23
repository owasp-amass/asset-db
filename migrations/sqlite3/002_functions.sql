-- +migrate Up

PRAGMA foreign_keys = ON;

-- Holds reusable, named SQL templates (CTEs for upserts, edge/tag helpers, etc.)
CREATE TABLE IF NOT EXISTS sql_templates (
  name TEXT PRIMARY KEY,
  sql  TEXT NOT NULL,                 -- the exact SQL to Prepare (WITH ... SELECT ...)
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);

-- Optional: versioning for migrations (for your own pipeline)
CREATE TABLE IF NOT EXISTS migration_meta (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  tag TEXT NOT NULL,
  notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_sql_templates_updated_at ON sql_templates(updated_at);

-- Helpful read-only views (keep them close to ingestion)
CREATE VIEW IF NOT EXISTS v_resolutions AS
SELECT fq.entity_id AS fqdn_id, fq.display_value AS fqdn,
       ip.entity_id AS ip_id,   ip.display_value AS ip,
       e.edge_id, e.created_at, e.updated_at, e.content
FROM entities fq
JOIN entity_type_lu tf ON tf.id=fq.type_id AND tf.name='fqdn'
JOIN edges e ON e.from_entity_id=fq.entity_id
JOIN edge_type_lu te ON te.id=e.etype_id AND te.name='RESOLVES_TO'
JOIN entities ip ON ip.entity_id=e.to_entity_id
JOIN entity_type_lu tip ON tip.id=ip.type_id AND tip.name='ipaddress';

CREATE VIEW IF NOT EXISTS v_entity_tags AS
SELECT e.entity_id, tlu.name AS entity_type, e.display_value,
       tg.namespace, tg.name AS tag, tg.value, tg.meta, m.details, m.updated_at
FROM entities e
JOIN entity_type_lu tlu ON tlu.id=e.type_id
JOIN entity_tag_map m ON m.entity_id=e.entity_id
JOIN tags tg ON tg.tag_id=m.tag_id;

-- Mark this migration
INSERT INTO migration_meta(tag, notes) VALUES ('install-sql-templates', 'Catalog table + helper views created');

-- +migrate Down

DROP VIEW IF EXISTS v_entity_tags;
DROP VIEW IF EXISTS v_resolutions;

DROP INDEX IF EXISTS idx_sql_templates_updated_at;
DROP TABLE IF EXISTS migration_meta;
DROP TABLE IF EXISTS sql_templates;