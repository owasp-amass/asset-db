-- +migrate Up

-- ============================================================================
-- OWASP Amass — High-performance schema for SQLite (3.38+ recommended)
-- - Normalized Property Graph Schema implemented on SQLite
-- - Uses JSON1 (json_valid/json_extract/json_patch)
-- - Lowercased “normalized” columns for case-insensitive uniqueness
-- - Native UPSERT via INSERT ... ON CONFLICT
-- ============================================================================

PRAGMA foreign_keys = ON;

-- -----------------------------
-- Lookup tables (compact IDs)
-- -----------------------------
CREATE TABLE IF NOT EXISTS entity_type_lu (
  id    INTEGER PRIMARY KEY AUTOINCREMENT,
  name  TEXT COLLATE NOCASE NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS edge_type_lu (
  id    INTEGER PRIMARY KEY AUTOINCREMENT,
  name  TEXT COLLATE NOCASE NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS tag_type_lu (
  id    INTEGER PRIMARY KEY AUTOINCREMENT,
  name  TEXT COLLATE NOCASE NOT NULL UNIQUE
);

-- Seed common types (extend as needed)
INSERT OR IGNORE INTO entity_type_lu(name) VALUES
 ('account'),('autnumrecord'),('autonomoussystem'),('contactrecord'),('domainrecord'),('file'),
 ('fqdn'),('fundstransfer'),('identifier'),('ipaddress'),('ipnetrecord'),('location'),('netblock'),
 ('organization'),('person'),('phone'),('product'),('productrelease'),('service'),('tlscertificate'),
 ('url');

INSERT OR IGNORE INTO edge_type_lu(name) VALUES
 ('basicdnsrelation'),('portrelation'),('prefdnsrelation'),('simplerelation'),('srvdnsrelation');

INSERT OR IGNORE INTO tag_type_lu(name) VALUES
 ('dnsrecordproperty'),('simpleproperty'),('sourceproperty'),('vulnproperty');

-- -----------------------------
-- Core entity mapping
-- -----------------------------
CREATE TABLE IF NOT EXISTS entity (
  entity_id   INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  etype_id    INTEGER NOT NULL REFERENCES entity_type_lu(id),
  natural_key TEXT NOT NULL,
  table_name  TEXT COLLATE NOCASE NOT NULL,
  row_id      INTEGER NOT NULL,
  UNIQUE (etype_id, row_id),
  UNIQUE (etype_id, natural_key),
  UNIQUE (table_name, row_id)
);
CREATE INDEX IF NOT EXISTS idx_entity_created_at ON entity (created_at);
CREATE INDEX IF NOT EXISTS idx_entity_updated_at ON entity (updated_at);
CREATE INDEX IF NOT EXISTS idx_entity_etype_id ON entity (etype_id);
CREATE INDEX IF NOT EXISTS idx_entity_natural_key ON entity (natural_key);
CREATE INDEX IF NOT EXISTS idx_entity_table_name ON entity (table_name);
CREATE INDEX IF NOT EXISTS idx_entity_row_id ON entity (row_id);

-- -----------------------------
-- Graph edges & tags
-- -----------------------------
CREATE TABLE IF NOT EXISTS edge (
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
CREATE INDEX IF NOT EXISTS idx_edge_created_at ON edge (created_at);
CREATE INDEX IF NOT EXISTS idx_edge_updated_at ON edge (updated_at);
CREATE INDEX IF NOT EXISTS idx_edge_etype_id ON edge (etype_id);
CREATE INDEX IF NOT EXISTS idx_edge_label ON edge (label);
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

CREATE TABLE IF NOT EXISTS entity_tag (
  tag_id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  entity_id      INTEGER NOT NULL REFERENCES entity(entity_id) ON DELETE CASCADE,
  ttype_id       INTEGER NOT NULL REFERENCES tag_type_lu(id),
  property_name  TEXT NOT NULL,
  property_value TEXT NOT NULL,
  content        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(content)),
  UNIQUE (entity_id, ttype_id, property_name, property_value)
);
CREATE INDEX IF NOT EXISTS idx_entity_tag_created_at ON entity_tag_map (created_at);
CREATE INDEX IF NOT EXISTS idx_entity_tag_updated_at ON entity_tag_map (updated_at);
CREATE INDEX IF NOT EXISTS idx_entity_tag_entity_updated ON entity_tag_map (entity_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_entity_tag_entity_id ON entity_tag_map (entity_id);
CREATE INDEX IF NOT EXISTS idx_entity_tag_ttype_id ON entity_tag (ttype_id);
CREATE INDEX IF NOT EXISTS idx_entity_tag_property_name ON entity_tag (property_name);
CREATE INDEX IF NOT EXISTS idx_entity_tag_tt_name ON entity_tag (ttype_id, property_name);
CREATE INDEX IF NOT EXISTS idx_entity_tag_property_name_value ON entity_tag (property_name, property_value);
CREATE INDEX IF NOT EXISTS idx_entity_tag_ttype_name_value ON entity_tag (ttype_id, property_name, property_value);

CREATE TABLE IF NOT EXISTS edge_tag (
  tag_id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  edge_id        INTEGER NOT NULL REFERENCES edge(edge_id) ON DELETE CASCADE,
  ttype_id       INTEGER NOT NULL REFERENCES tag_type_lu(id),
  property_name  TEXT NOT NULL,
  property_value TEXT NOT NULL,
  content        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(content)),
  UNIQUE (edge_id, ttype_id, property_name, property_value)
);
CREATE INDEX IF NOT EXISTS idx_edge_tag_created_at ON edge_tag (created_at);
CREATE INDEX IF NOT EXISTS idx_edge_tag_updated_at ON edge_tag (updated_at);
CREATE INDEX IF NOT EXISTS idx_edge_tag_edge_updated ON edge_tag (edge_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_edge_tag_edge_id ON edge_tag (edge_id);
CREATE INDEX IF NOT EXISTS idx_edge_tag_ttype_id ON edge_tag (ttype_id);
CREATE INDEX IF NOT EXISTS idx_edge_tag_property_name ON edge_tag (property_name);
CREATE INDEX IF NOT EXISTS idx_edge_tag_tt_name ON edge_tag (ttype_id, property_name);
CREATE INDEX IF NOT EXISTS idx_edge_tag_property_name_value ON edge_tag (property_name, property_value);
CREATE INDEX IF NOT EXISTS idx_edge_tag_ttype_name_value ON edge_tag (ttype_id, property_name, property_value);

-- -----------------------------------------------
-- Asset tables (with normalized columns)
-- -----------------------------------------------

-- Accounts
CREATE TABLE IF NOT EXISTS account (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  unique_id      TEXT NOT NULL UNIQUE,
  account_type   TEXT NOT NULL,
  username       TEXT,
  account_number TEXT,
  attrs          TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);
CREATE INDEX IF NOT EXISTS idx_account_created_at ON account (created_at);
CREATE INDEX IF NOT EXISTS idx_account_updated_at ON account (updated_at);
CREATE INDEX IF NOT EXISTS idx_account_account_type ON account (account_type);
CREATE INDEX IF NOT EXISTS idx_account_username ON account (username);
CREATE INDEX IF NOT EXISTS idx_account_account_number ON account (account_number);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_account_ai
AFTER INSERT ON account
BEGIN
  INSERT INTO entity (etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='account' LIMIT 1), NEW.unique_id, 'account', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_account_au
AFTER UPDATE ON account
BEGIN
  INSERT INTO entity (etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='account' LIMIT 1), NEW.unique_id, 'account', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Autonomous System Registration records
CREATE TABLE IF NOT EXISTS autnumrecord (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  record_name  TEXT,
  handle       TEXT NOT NULL UNIQUE,
  asn          INTEGER NOT NULL UNIQUE,
  whois_server TEXT,
  whois_norm   TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(whois_server)) STORED,
  attrs        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);
CREATE INDEX IF NOT EXISTS idx_autnumrecord_created_at ON autnumrecord (created_at);
CREATE INDEX IF NOT EXISTS idx_autnumrecord_updated_at ON autnumrecord (updated_at);
CREATE INDEX IF NOT EXISTS idx_autnumrecord_name ON autnumrecord (record_name);
CREATE INDEX IF NOT EXISTS idx_autnumrecord_whois_server ON autnumrecord (whois_norm);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_autnumrecord_ai
AFTER INSERT ON autnumrecord
BEGIN
  INSERT INTO entity (etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='autnumrecord' LIMIT 1), NEW.handle, 'autnumrecord', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_autnumrecord_au
AFTER UPDATE ON autnumrecord
BEGIN
  INSERT INTO entity (etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='autnumrecord' LIMIT 1), NEW.handle, 'autnumrecord', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Autonomous System records
CREATE TABLE IF NOT EXISTS autonomoussystem (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  asn        INTEGER NOT NULL UNIQUE,
  attrs      TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);
CREATE INDEX IF NOT EXISTS idx_autonomoussystem_created_at ON autonomoussystem (created_at);
CREATE INDEX IF NOT EXISTS idx_autonomoussystem_updated_at ON autonomoussystem (updated_at);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_autonomoussystem_ai
AFTER INSERT ON autonomoussystem
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='autonomoussystem' LIMIT 1), CAST(NEW.asn AS TEXT), 'autonomoussystem', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_autonomoussystem_au
AFTER UPDATE ON autonomoussystem
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='autonomoussystem' LIMIT 1), CAST(NEW.asn AS TEXT), 'autonomoussystem', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Contact records
CREATE TABLE IF NOT EXISTS contactrecord (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  discovered_at TEXT NOT NULL UNIQUE,
  attrs         TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);
CREATE INDEX IF NOT EXISTS idx_contactrecord_created_at ON contactrecord (created_at);
CREATE INDEX IF NOT EXISTS idx_contactrecord_updated_at ON contactrecord (updated_at);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_contactrecord_ai
AFTER INSERT ON contactrecord
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='contactrecord' LIMIT 1), NEW.discovered_at, 'contactrecord', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_contactrecord_au
AFTER UPDATE ON contactrecord
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='contactrecord' LIMIT 1), NEW.discovered_at, 'contactrecord', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Domain Registration records
-- domain/fqdn/url host: normalized lowercased columns for CI uniqueness
CREATE TABLE IF NOT EXISTS domainrecord (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  record_name     TEXT NOT NULL,
  domain          TEXT NOT NULL UNIQUE,
  domain_norm     TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(domain)) STORED,
  punycode        TEXT,
  punycode_norm   TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(punycode)) STORED,
  extension       TEXT,
  whois_server    TEXT,
  whois_norm      TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(whois_server)) STORED,
  object_id       TEXT,
  attrs           TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs)),
  UNIQUE(domain_norm)
);
CREATE INDEX IF NOT EXISTS idx_domainrecord_created_at ON domainrecord (created_at);
CREATE INDEX IF NOT EXISTS idx_domainrecord_updated_at ON domainrecord (updated_at);
CREATE INDEX IF NOT EXISTS idx_domainrecord_name ON domainrecord (record_name);
CREATE INDEX IF NOT EXISTS idx_domainrecord_extension ON domainrecord (extension);
CREATE INDEX IF NOT EXISTS idx_domainrecord_punycode ON domainrecord (punycode_norm);
CREATE INDEX IF NOT EXISTS idx_domainrecord_whois_server ON domainrecord (whois_norm);
CREATE INDEX IF NOT EXISTS idx_domainrecord_object_id ON domainrecord (object_id);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_domainrecord_ai
AFTER INSERT ON domainrecord
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='domainrecord' LIMIT 1), NEW.domain_norm, 'domainrecord', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_domainrecord_au
AFTER UPDATE ON domainrecord
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='domainrecord' LIMIT 1), NEW.domain_norm, 'domainrecord', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Files
CREATE TABLE IF NOT EXISTS file (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  file_url   TEXT NOT NULL UNIQUE,
  basename   TEXT,
  file_type  TEXT,
  attrs      TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);
CREATE INDEX IF NOT EXISTS idx_file_created_at ON file (created_at);
CREATE INDEX IF NOT EXISTS idx_file_updated_at ON file (updated_at);
CREATE INDEX IF NOT EXISTS idx_file_basename ON file (basename);
CREATE INDEX IF NOT EXISTS idx_file_file_type ON file (file_type);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_file_ai
AFTER INSERT ON file
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='file' LIMIT 1), NEW.file_url, 'file', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_file_au
AFTER UPDATE ON file
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='file' LIMIT 1), NEW.file_url, 'file', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Fully Qualified Domain Names (FQDNs)
CREATE TABLE IF NOT EXISTS fqdn (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  fqdn       TEXT NOT NULL,
  fqdn_norm  TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(fqdn)) STORED,
  attrs      TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs)),
  UNIQUE(fqdn_norm)
);
CREATE INDEX IF NOT EXISTS idx_fqdn_created_at ON fqdn (created_at);
CREATE INDEX IF NOT EXISTS idx_fqdn_updated_at ON fqdn (updated_at);

-- Fires when we insert a new fqdn row
-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_fqdn_ai
AFTER INSERT ON fqdn
BEGIN
  INSERT INTO entity (etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='fqdn' LIMIT 1), lower(NEW.fqdn), 'fqdn', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Fires when an UPSERT takes the DO UPDATE path
-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_fqdn_au
AFTER UPDATE OF fqdn ON fqdn
BEGIN
  INSERT INTO entity (etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='fqdn' LIMIT 1), lower(NEW.fqdn), 'fqdn', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Funds Transfer records
CREATE TABLE IF NOT EXISTS fundstransfer (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  unique_id        TEXT NOT NULL UNIQUE,
  amount           REAL NOT NULL,
  reference_number TEXT,
  attrs            TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_created_at ON fundstransfer (created_at);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_updated_at ON fundstransfer (updated_at);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_amount ON fundstransfer (amount);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_reference_number ON fundstransfer (reference_number);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_fundstransfer_ai
AFTER INSERT ON fundstransfer
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='fundstransfer' LIMIT 1), NEW.unique_id, 'fundstransfer', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_fundstransfer_au
AFTER UPDATE ON fundstransfer
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='fundstransfer' LIMIT 1), NEW.unique_id, 'fundstransfer', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Identifiers
CREATE TABLE IF NOT EXISTS identifier (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  unique_id  TEXT NOT NULL UNIQUE,
  id_value   TEXT NOT NULL,
  id_type    TEXT NOT NULL,
  attrs      TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs)),
  UNIQUE(id_value, id_type)
);
CREATE INDEX IF NOT EXISTS idx_identifier_created_at ON identifier (created_at);
CREATE INDEX IF NOT EXISTS idx_identifier_updated_at ON identifier (updated_at);
CREATE INDEX IF NOT EXISTS idx_identifier_id_value ON identifier (id_value);
CREATE INDEX IF NOT EXISTS idx_identifier_id_type ON identifier (id_type);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_identifier_ai
AFTER INSERT ON identifier
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='identifier' LIMIT 1), NEW.unique_id, 'identifier', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_identifier_au
AFTER UPDATE ON identifier
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='identifier' LIMIT 1), NEW.unique_id, 'identifier', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- IP Addresses
CREATE TABLE IF NOT EXISTS ipaddress (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  ip_address TEXT NOT NULL UNIQUE,
  attrs      TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);
CREATE INDEX IF NOT EXISTS idx_ipaddress_created_at ON ipaddress (created_at);
CREATE INDEX IF NOT EXISTS idx_ipaddress_updated_at ON ipaddress (updated_at);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_ipaddress_ai
AFTER INSERT ON ipaddress
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='ipaddress' LIMIT 1), NEW.ip_address, 'ipaddress', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_ipaddress_au
AFTER UPDATE ON ipaddress
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='ipaddress' LIMIT 1), NEW.ip_address, 'ipaddress', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- IP Network Registration records
CREATE TABLE IF NOT EXISTS ipnetrecord (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  record_cidr   TEXT NOT NULL UNIQUE,
  record_name   TEXT NOT NULL,
  handle        TEXT NOT NULL UNIQUE,
  whois_server  TEXT,
  whois_norm    TEXT GENERATED ALWAYS AS (lower(whois_server)) STORED,
  parent_handle TEXT,
  start_address TEXT,
  end_address   TEXT,
  attrs         TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_created_at ON ipnetrecord (created_at);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_updated_at ON ipnetrecord (updated_at);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_name ON ipnetrecord (record_name);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_start_address ON ipnetrecord (start_address);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_end_address ON ipnetrecord (end_address);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_whois_server ON ipnetrecord (whois_norm);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_parent_handle ON ipnetrecord (parent_handle);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_ipnetrecord_ai
AFTER INSERT ON ipnetrecord
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='ipnetrecord' LIMIT 1), NEW.handle, 'ipnetrecord', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_ipnetrecord_au
AFTER UPDATE ON ipnetrecord
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='ipnetrecord' LIMIT 1), NEW.handle, 'ipnetrecord', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Locations
CREATE TABLE IF NOT EXISTS location (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  street_address  TEXT NOT NULL,
  street_address_norm TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(street_address)) STORED,
  building        TEXT,
  building_norm   TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(building)) STORED,
  building_number TEXT,
  building_number_norm TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(building_number)) STORED,
  street_name     TEXT,
  street_name_norm TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(street_name)) STORED,
  unit            TEXT,
  unit_norm       TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(unit)) STORED,
  city            TEXT NOT NULL,
  city_norm       TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(city)) STORED,
  locality        TEXT,
  locality_norm   TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(locality)) STORED,
  province        TEXT,
  province_norm   TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(province)) STORED,
  country         TEXT NOT NULL,
  country_norm    TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(country)) STORED,
  postal_code     TEXT,
  attrs           TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs)),
  UNIQUE(street_address_norm)
);
CREATE INDEX IF NOT EXISTS idx_location_created_at ON location (created_at);
CREATE INDEX IF NOT EXISTS idx_location_updated_at ON location (updated_at);
CREATE INDEX IF NOT EXISTS idx_location_building ON location (building_norm);
CREATE INDEX IF NOT EXISTS idx_location_building_number ON location (building_number_norm);
CREATE INDEX IF NOT EXISTS idx_location_street_name ON location (street_name_norm);
CREATE INDEX IF NOT EXISTS idx_location_unit ON location (unit_norm);
CREATE INDEX IF NOT EXISTS idx_location_city ON location (city_norm);
CREATE INDEX IF NOT EXISTS idx_location_locality ON location (locality_norm);
CREATE INDEX IF NOT EXISTS idx_location_province ON location (province_norm);
CREATE INDEX IF NOT EXISTS idx_location_country ON location (country_norm);
CREATE INDEX IF NOT EXISTS idx_location_postal_code ON location (postal_code);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_location_ai
AFTER INSERT ON location
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='location' LIMIT 1), NEW.street_address_norm, 'location', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_location_au
AFTER UPDATE ON location
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='location' LIMIT 1), NEW.street_address_norm, 'location', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Netblocks
CREATE TABLE IF NOT EXISTS netblock (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  netblock_cidr TEXT NOT NULL UNIQUE,
  attrs         TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);
CREATE INDEX IF NOT EXISTS idx_netblock_created_at ON netblock (created_at);
CREATE INDEX IF NOT EXISTS idx_netblock_updated_at ON netblock (updated_at);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_netblock_ai
AFTER INSERT ON netblock
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='netblock' LIMIT 1), NEW.netblock_cidr, 'netblock', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_netblock_au
AFTER UPDATE ON netblock
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='netblock' LIMIT 1), NEW.netblock_cidr, 'netblock', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Organizations
CREATE TABLE IF NOT EXISTS organization (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  unique_id       TEXT NOT NULL UNIQUE,
  org_name        TEXT,
  legal_name      TEXT NOT NULL,
  jurisdiction    TEXT,
  registration_id TEXT,
  attrs           TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);
CREATE INDEX IF NOT EXISTS idx_organization_created_at ON organization (created_at);
CREATE INDEX IF NOT EXISTS idx_organization_updated_at ON organization (updated_at);
CREATE INDEX IF NOT EXISTS idx_organization_org_name ON organization (org_name);
CREATE INDEX IF NOT EXISTS idx_organization_legal_name ON organization (legal_name);
CREATE INDEX IF NOT EXISTS idx_organization_jurisdiction ON organization (jurisdiction);
CREATE INDEX IF NOT EXISTS idx_organization_registration_id ON organization (registration_id);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_organization_ai
AFTER INSERT ON organization
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='organization' LIMIT 1), NEW.unique_id, 'organization', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_organization_au
AFTER UPDATE ON organization
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='organization' LIMIT 1), NEW.unique_id, 'organization', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Persons
CREATE TABLE IF NOT EXISTS person (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  full_name   TEXT,
  unique_id   TEXT NOT NULL UNIQUE,
  first_name  TEXT,
  family_name TEXT,
  attrs       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);
CREATE INDEX IF NOT EXISTS idx_person_created_at ON person (created_at);
CREATE INDEX IF NOT EXISTS idx_person_updated_at ON person (updated_at);
CREATE INDEX IF NOT EXISTS idx_person_full_name ON person (full_name);
CREATE INDEX IF NOT EXISTS idx_person_first_name ON person (first_name);
CREATE INDEX IF NOT EXISTS idx_person_family_name ON person (family_name);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_person_ai
AFTER INSERT ON person
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='person' LIMIT 1), NEW.unique_id, 'person', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_person_au
AFTER UPDATE ON person
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='person' LIMIT 1), NEW.unique_id, 'person', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Phone numbers
CREATE TABLE IF NOT EXISTS phone (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  e164         TEXT NOT NULL UNIQUE,
  country_code INTEGER,
  attrs        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);
CREATE INDEX IF NOT EXISTS idx_phone_created_at ON phone (created_at);
CREATE INDEX IF NOT EXISTS idx_phone_updated_at ON phone (updated_at);
CREATE INDEX IF NOT EXISTS idx_phone_country_code ON phone (country_code);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_phone_ai
AFTER INSERT ON phone
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='phone' LIMIT 1), NEW.e164, 'phone', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_phone_au
AFTER UPDATE ON phone
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='phone' LIMIT 1), NEW.e164, 'phone', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Products
CREATE TABLE IF NOT EXISTS product (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  unique_id    TEXT NOT NULL UNIQUE,
  product_name TEXT NOT NULL,
  product_type TEXT,
  attrs        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);
CREATE INDEX IF NOT EXISTS idx_product_created_at ON product (created_at);
CREATE INDEX IF NOT EXISTS idx_product_updated_at ON product (updated_at);
CREATE INDEX IF NOT EXISTS idx_product_name ON product (product_name);
CREATE INDEX IF NOT EXISTS idx_product_type ON product (product_type);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_product_ai
AFTER INSERT ON product
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='product' LIMIT 1), NEW.unique_id, 'product', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_product_au
AFTER UPDATE ON product
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='product' LIMIT 1), NEW.unique_id, 'product', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Product Releases
CREATE TABLE IF NOT EXISTS productrelease (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  release_name TEXT NOT NULL,
  release_name_norm TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(release_name)) STORED,
  attrs        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs)),
  UNIQUE(release_name_norm)
);
CREATE INDEX IF NOT EXISTS idx_productrelease_created_at ON productrelease (created_at);
CREATE INDEX IF NOT EXISTS idx_productrelease_updated_at ON productrelease (updated_at);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_productrelease_ai
AFTER INSERT ON productrelease
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='productrelease' LIMIT 1), NEW.release_name_norm, 'productrelease', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_productrelease_au
AFTER UPDATE ON productrelease
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='productrelease' LIMIT 1), NEW.release_name_norm, 'productrelease', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Services
CREATE TABLE IF NOT EXISTS service (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  unique_id     TEXT NOT NULL UNIQUE,
  service_type  TEXT NOT NULL,
  attrs         TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);
CREATE INDEX IF NOT EXISTS idx_service_created_at ON service (created_at);
CREATE INDEX IF NOT EXISTS idx_service_updated_at ON service (updated_at);
CREATE INDEX IF NOT EXISTS idx_service_service_type ON service (service_type);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_service_ai
AFTER INSERT ON service
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='service' LIMIT 1), NEW.unique_id, 'service', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_service_au
AFTER UPDATE ON service
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='service' LIMIT 1), NEW.unique_id, 'service', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- TLS Certificates
CREATE TABLE IF NOT EXISTS tlscertificate (
  id                       INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  serial_number            TEXT NOT NULL UNIQUE,
  subject_common_name      TEXT NOT NULL,
  subject_common_name_norm TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(subject_common_name)) STORED,
  attrs                    TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_created_at ON tlscertificate (created_at);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_updated_at ON tlscertificate (updated_at);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_subject_common_name ON tlscertificate (subject_common_name_norm);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_tlscertificate_ai
AFTER INSERT ON tlscertificate
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='tlscertificate' LIMIT 1), NEW.serial_number, 'tlscertificate', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_tlscertificate_au
AFTER UPDATE ON tlscertificate
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='tlscertificate' LIMIT 1), NEW.serial_number, 'tlscertificate', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Universal Resource Locators (URLs)
CREATE TABLE IF NOT EXISTS url (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  raw_url    TEXT NOT NULL UNIQUE,
  scheme     TEXT,
  attrs      TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);
CREATE INDEX IF NOT EXISTS idx_url_created_at ON url (created_at);
CREATE INDEX IF NOT EXISTS idx_url_updated_at ON url (updated_at);
CREATE INDEX IF NOT EXISTS idx_url_scheme ON url (scheme);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_url_ai
AFTER INSERT ON url
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='url' LIMIT 1), NEW.raw_url, 'url', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_url_au
AFTER UPDATE ON url
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='url' LIMIT 1), NEW.raw_url, 'url', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate Down

DROP TRIGGER IF EXISTS trg_url_au;
DROP TRIGGER IF EXISTS trg_url_ai;
DROP INDEX IF EXISTS idx_url_scheme;
DROP INDEX IF EXISTS idx_url_updated_at;
DROP INDEX IF EXISTS idx_url_created_at;
DROP TABLE IF EXISTS url;

DROP TRIGGER IF EXISTS trg_tlscertificate_au;
DROP TRIGGER IF EXISTS trg_tlscertificate_ai;
DROP INDEX IF EXISTS idx_tlscertificate_subject_common_name;
DROP INDEX IF EXISTS idx_tlscertificate_updated_at;
DROP INDEX IF EXISTS idx_tlscertificate_created_at;
DROP TABLE IF EXISTS tlscertificate;

DROP TRIGGER IF EXISTS trg_service_au;
DROP TRIGGER IF EXISTS trg_service_ai;
DROP INDEX IF EXISTS idx_service_service_type;
DROP INDEX IF EXISTS idx_service_updated_at;
DROP INDEX IF EXISTS idx_service_created_at;
DROP TABLE IF EXISTS service;

DROP TRIGGER IF EXISTS trg_productrelease_au;
DROP TRIGGER IF EXISTS trg_productrelease_ai;
DROP INDEX IF EXISTS idx_productrelease_updated_at;
DROP INDEX IF EXISTS idx_productrelease_created_at;
DROP TABLE IF EXISTS productrelease;

DROP TRIGGER IF EXISTS trg_product_au;
DROP TRIGGER IF EXISTS trg_product_ai;
DROP INDEX IF EXISTS idx_product_type;
DROP INDEX IF EXISTS idx_product_name;
DROP INDEX IF EXISTS idx_product_updated_at;
DROP INDEX IF EXISTS idx_product_created_at;
DROP TABLE IF EXISTS product;

DROP TRIGGER IF EXISTS trg_phone_au;
DROP TRIGGER IF EXISTS trg_phone_ai;
DROP INDEX IF EXISTS idx_phone_country_code;
DROP INDEX IF EXISTS idx_phone_updated_at;
DROP INDEX IF EXISTS idx_phone_created_at;
DROP TABLE IF EXISTS phone;

DROP TRIGGER IF EXISTS trg_person_au;
DROP TRIGGER IF EXISTS trg_person_ai;
DROP INDEX IF EXISTS idx_person_family_name;
DROP INDEX IF EXISTS idx_person_first_name;
DROP INDEX IF EXISTS idx_person_full_name;
DROP INDEX IF EXISTS idx_person_updated_at;
DROP INDEX IF EXISTS idx_person_created_at;
DROP TABLE IF EXISTS person;

DROP TRIGGER IF EXISTS trg_organization_au;
DROP TRIGGER IF EXISTS trg_organization_ai;
DROP INDEX IF EXISTS idx_organization_registration_id;
DROP INDEX IF EXISTS idx_organization_jurisdiction;
DROP INDEX IF EXISTS idx_organization_org_name;
DROP INDEX IF EXISTS idx_organization_legal_name;
DROP INDEX IF EXISTS idx_organization_updated_at;
DROP INDEX IF EXISTS idx_organization_created_at;
DROP TABLE IF EXISTS organization;

DROP TRIGGER IF EXISTS trg_netblock_au;
DROP TRIGGER IF EXISTS trg_netblock_ai;
DROP INDEX IF EXISTS idx_netblock_updated_at;
DROP INDEX IF EXISTS idx_netblock_created_at;
DROP TABLE IF EXISTS netblock;

DROP TRIGGER IF EXISTS trg_location_au;
DROP TRIGGER IF EXISTS trg_location_ai;
DROP INDEX IF EXISTS idx_location_postal_code;
DROP INDEX IF EXISTS idx_location_country;
DROP INDEX IF EXISTS idx_location_city;
DROP INDEX IF EXISTS idx_location_locality;
DROP INDEX IF EXISTS idx_location_unit;
DROP INDEX IF EXISTS idx_location_street_name;
DROP INDEX IF EXISTS idx_location_province;
DROP INDEX IF EXISTS idx_location_building_number;
DROP INDEX IF EXISTS idx_location_building;
DROP INDEX IF EXISTS idx_location_updated_at;
DROP INDEX IF EXISTS idx_location_created_at;
DROP TABLE IF EXISTS location;

DROP TRIGGER IF EXISTS trg_ipnetrecord_au;
DROP TRIGGER IF EXISTS trg_ipnetrecord_ai;
DROP INDEX IF EXISTS idx_ipnetrecord_parent_handle;
DROP INDEX IF EXISTS idx_ipnetrecord_whois_server;
DROP INDEX IF EXISTS idx_ipnetrecord_end_address;
DROP INDEX IF EXISTS idx_ipnetrecord_start_address;
DROP INDEX IF EXISTS idx_ipnetrecord_name;
DROP INDEX IF EXISTS idx_ipnetrecord_updated_at;
DROP INDEX IF EXISTS idx_ipnetrecord_created_at;
DROP TABLE IF EXISTS ipnetrecord;

DROP TRIGGER IF EXISTS trg_ipaddress_au;
DROP TRIGGER IF EXISTS trg_ipaddress_ai;
DROP INDEX IF EXISTS idx_ipaddress_updated_at;
DROP INDEX IF EXISTS idx_ipaddress_created_at;
DROP TABLE IF EXISTS ipaddress;

DROP TRIGGER IF EXISTS trg_identifier_au;
DROP TRIGGER IF EXISTS trg_identifier_ai;
DROP INDEX IF EXISTS idx_identifier_id_type;
DROP INDEX IF EXISTS idx_identifier_id_value;
DROP INDEX IF EXISTS idx_identifier_updated_at;
DROP INDEX IF EXISTS idx_identifier_created_at;
DROP TABLE IF EXISTS identifier;

DROP TRIGGER IF EXISTS trg_fundstransfer_au;
DROP TRIGGER IF EXISTS trg_fundstransfer_ai;
DROP INDEX IF EXISTS idx_fundstransfer_reference_number;
DROP INDEX IF EXISTS idx_fundstransfer_amount;
DROP INDEX IF EXISTS idx_fundstransfer_updated_at;
DROP INDEX IF EXISTS idx_fundstransfer_created_at;
DROP TABLE IF EXISTS fundstransfer;

DROP TRIGGER IF EXISTS trg_fqdn_au;
DROP TRIGGER IF EXISTS trg_fqdn_ai;
DROP INDEX IF EXISTS idx_fqdn_updated_at;
DROP INDEX IF EXISTS idx_fqdn_created_at;
DROP TABLE IF EXISTS fqdn;

DROP TRIGGER IF EXISTS trg_file_au;
DROP TRIGGER IF EXISTS trg_file_ai;
DROP INDEX IF EXISTS idx_file_file_type;
DROP INDEX IF EXISTS idx_file_basename;
DROP INDEX IF EXISTS idx_file_updated_at;
DROP INDEX IF EXISTS idx_file_created_at;
DROP TABLE IF EXISTS file;

DROP TRIGGER IF EXISTS trg_domainrecord_au;
DROP TRIGGER IF EXISTS trg_domainrecord_ai;
DROP INDEX IF EXISTS idx_domainrecord_object_id;
DROP INDEX IF EXISTS idx_domainrecord_whois_server;
DROP INDEX IF EXISTS idx_domainrecord_punycode;
DROP INDEX IF EXISTS idx_domainrecord_extension;
DROP INDEX IF EXISTS idx_domainrecord_name;
DROP INDEX IF EXISTS idx_domainrecord_updated_at;
DROP INDEX IF EXISTS idx_domainrecord_created_at;
DROP TABLE IF EXISTS domainrecord;

DROP TRIGGER IF EXISTS trg_contactrecord_au;
DROP TRIGGER IF EXISTS trg_contactrecord_ai;
DROP INDEX IF EXISTS idx_contactrecord_updated_at;
DROP INDEX IF EXISTS idx_contactrecord_created_at;
DROP TABLE IF EXISTS contactrecord;

DROP TRIGGER IF EXISTS trg_autonomoussystem_au;
DROP TRIGGER IF EXISTS trg_autonomoussystem_ai;
DROP INDEX IF EXISTS idx_autonomoussystem_updated_at;
DROP INDEX IF EXISTS idx_autonomoussystem_created_at;
DROP TABLE IF EXISTS autonomoussystem;

DROP TRIGGER IF EXISTS trg_autnumrecord_au;
DROP TRIGGER IF EXISTS trg_autnumrecord_ai;
DROP INDEX IF EXISTS idx_autnumrecord_whois_server;
DROP INDEX IF EXISTS idx_autnumrecord_name;
DROP INDEX IF EXISTS idx_autnumrecord_updated_at;
DROP INDEX IF EXISTS idx_autnumrecord_created_at;
DROP TABLE IF EXISTS autnumrecord;

DROP TRIGGER IF EXISTS trg_account_au;
DROP TRIGGER IF EXISTS trg_account_ai;
DROP INDEX IF EXISTS idx_account_account_number;
DROP INDEX IF EXISTS idx_account_username;
DROP INDEX IF EXISTS idx_account_account_type;
DROP INDEX IF EXISTS idx_account_updated_at;
DROP INDEX IF EXISTS idx_account_created_at;
DROP TABLE IF EXISTS account;

DROP INDEX IF EXISTS idx_edge_tag_ttype_name_value;
DROP INDEX IF EXISTS idx_edge_tag_property_name_value;
DROP INDEX IF EXISTS idx_edge_tag_tt_name;
DROP INDEX IF EXISTS idx_edge_tag_property_name;
DROP INDEX IF EXISTS idx_edge_tag_ttype_id;
DROP INDEX IF EXISTS idx_edge_tag_edge_id;
DROP INDEX IF EXISTS idx_edge_tag_edge_updated;
DROP INDEX IF EXISTS idx_edge_tag_updated_at;
DROP INDEX IF EXISTS idx_edge_tag_created_at;
DROP TABLE IF EXISTS edge_tag;

DROP INDEX IF EXISTS idx_entity_tag_ttype_name_value;
DROP INDEX IF EXISTS idx_entity_tag_property_name_value;
DROP INDEX IF EXISTS idx_entity_tag_tt_name;
DROP INDEX IF EXISTS idx_entity_tag_property_name;
DROP INDEX IF EXISTS idx_entity_tag_ttype_id;
DROP INDEX IF EXISTS idx_entity_tag_entity_id;
DROP INDEX IF EXISTS idx_entity_tag_entity_updated;
DROP INDEX IF EXISTS idx_entity_tag_updated_at;
DROP INDEX IF EXISTS idx_entity_tag_created_at;
DROP TABLE IF EXISTS entity_tag;

DROP TRIGGER IF EXISTS trg_edge_au;
DROP INDEX IF EXISTS idx_edge_to;
DROP INDEX IF EXISTS idx_edge_from;
DROP INDEX IF EXISTS idx_edge_to_id;
DROP INDEX IF EXISTS idx_edge_from_id;
DROP INDEX IF EXISTS idx_edge_label;
DROP INDEX IF EXISTS idx_edge_etype_id;
DROP INDEX IF EXISTS idx_edge_updated_at;
DROP INDEX IF EXISTS idx_edge_created_at;
DROP TABLE IF EXISTS edge;

DROP INDEX IF EXISTS idx_entity_row_id;
DROP INDEX IF EXISTS idx_entity_table_name;
DROP INDEX IF EXISTS idx_entity_natural_key;
DROP INDEX IF EXISTS idx_entity_etype_id;
DROP INDEX IF EXISTS idx_entity_updated_at;
DROP INDEX IF EXISTS idx_entity_created_at;
DROP TABLE IF EXISTS entity;

DROP TABLE IF EXISTS tag_type_lu;
DROP TABLE IF EXISTS edge_type_lu;
DROP TABLE IF EXISTS entity_type_lu;