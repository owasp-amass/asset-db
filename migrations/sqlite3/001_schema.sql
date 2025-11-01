-- +migrate Up

-- ============================================================================
-- OWASP Amass — High-performance schema for SQLite (3.38+ recommended)
-- - Normalized Property Graph Schema implemented on SQLite
-- - Uses JSON1 (json_valid/json_extract/json_patch)
-- - Lowercased “normalized” columns for case-insensitive uniqueness
-- - Native UPSERT via INSERT ... ON CONFLICT
-- - No partitions (SQLite), but compact indexes
-- ============================================================================

PRAGMA foreign_keys = ON;

-- -----------------------------
-- Lookup tables (compact IDs)
-- -----------------------------
CREATE TABLE IF NOT EXISTS entity_type_lu (
  id    INTEGER PRIMARY KEY AUTOINCREMENT,
  name  TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS edge_type_lu (
  id    INTEGER PRIMARY KEY AUTOINCREMENT,
  name  TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS tag_type_lu (
  id    INTEGER PRIMARY KEY AUTOINCREMENT,
  name  TEXT NOT NULL UNIQUE
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
 ('dnsrecordproperty'),('simpleproperty'),('sourceproperty'),('vulnproperty'),('cacheproperty');

-- -----------------------------
-- Core entity & mapping
-- -----------------------------
CREATE TABLE IF NOT EXISTS entity (
  entity_id     INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  type_id       INTEGER NOT NULL REFERENCES entity_type_lu(id),
  display_value TEXT NOT NULL,
  attrs         TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs)),
  UNIQUE (type_id, display_value)
);
CREATE INDEX IF NOT EXISTS idx_entity_type ON entity(type_id);
CREATE INDEX IF NOT EXISTS idx_entity_display ON entity(display_value);

CREATE TABLE IF NOT EXISTS entity_ref (
  ref_id     INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_id  INTEGER NOT NULL REFERENCES entity(entity_id) ON DELETE CASCADE,
  table_name TEXT NOT NULL,
  row_id     INTEGER NOT NULL,
  UNIQUE (table_name, row_id),
  UNIQUE (entity_id, table_name, row_id)
);
CREATE INDEX IF NOT EXISTS idx_entity_ref_entity ON entity_ref(entity_id);

-- -----------------------------
-- Graph edges & tags
-- -----------------------------
CREATE TABLE IF NOT EXISTS edge (
  edge_id        INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  etype_id       INTEGER NOT NULL REFERENCES edge_type_lu(id),
  label          TEXT NOT NULL,
  content        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(content)),
  from_entity_id INTEGER NOT NULL REFERENCES entity(entity_id) ON DELETE CASCADE,
  to_entity_id   INTEGER NOT NULL REFERENCES entity(entity_id) ON DELETE CASCADE,
  UNIQUE (etype_id, from_entity_id, to_entity_id, label),
  CHECK (from_entity_id <> to_entity_id)
);
CREATE INDEX IF NOT EXISTS idx_edge_from ON edge(from_entity_id, etype_id, to_entity_id);
CREATE INDEX IF NOT EXISTS idx_edge_to   ON edge(to_entity_id, etype_id, from_entity_id);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_edge_au
AFTER UPDATE OF content ON edge
BEGIN
  UPDATE edge SET updated_at = CURRENT_TIMESTAMP WHERE edge_id = NEW.edge_id;
END;
-- +migrate StatementEnd

CREATE TABLE IF NOT EXISTS tag (
  tag_id          INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  ttype_id        INTEGER NOT NULL REFERENCES tag_type_lu(id),
  property_name   TEXT NOT NULL,
  property_value  TEXT NOT NULL,
  content         TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(content)),
  UNIQUE (ttype_id, property_name, property_value)
);
CREATE INDEX IF NOT EXISTS idx_tag_tt_name ON tag(ttype_id, property_name);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_tag_au
AFTER UPDATE OF content, property_value ON tag
BEGIN
  UPDATE tag SET updated_at = CURRENT_TIMESTAMP WHERE tag_id = NEW.tag_id;
END;
-- +migrate StatementEnd

CREATE TABLE IF NOT EXISTS entity_tag_map (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  entity_id  INTEGER NOT NULL REFERENCES entity(entity_id) ON DELETE CASCADE,
  tag_id     INTEGER NOT NULL REFERENCES tag(tag_id) ON DELETE CASCADE,
  UNIQUE (entity_id, tag_id)
);

CREATE TABLE IF NOT EXISTS edge_tag_map (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  edge_id    INTEGER NOT NULL REFERENCES edge(edge_id) ON DELETE CASCADE,
  tag_id     INTEGER NOT NULL REFERENCES tag(tag_id) ON DELETE CASCADE,
  UNIQUE (edge_id, tag_id)
);

-- -----------------------------------------------
-- Asset tables (with normalized columns)
-- -----------------------------------------------

-- Accounts

CREATE TABLE IF NOT EXISTS account (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  unique_id   TEXT NOT NULL UNIQUE,
  account_type TEXT NOT NULL,
  username    TEXT,
  account_number TEXT,
  balance REAL,
  active INTEGER
);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_account_ai
AFTER INSERT ON account
BEGIN
  INSERT INTO entity (type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='account'), NEW.unique_id, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref (entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='account') AND display_value=NEW.unique_id),
    'account', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_account_au
AFTER UPDATE ON account
BEGIN
  INSERT INTO entity (type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='account'), NEW.unique_id, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Autonomous System Registration records

CREATE TABLE IF NOT EXISTS autnumrecord (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  record_name TEXT,
  handle TEXT NOT NULL UNIQUE,
  asn INTEGER NOT NULL UNIQUE,
  record_status TEXT,
  created_date TEXT,
  updated_date TEXT,
  whois_server TEXT
);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_autnumrecord_ai
AFTER INSERT ON autnumrecord
BEGIN
  INSERT INTO entity (type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='autnumrecord'), NEW.handle, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='autnumrecord') AND display_value=NEW.handle),
    'autnumrecord', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_autnumrecord_au
AFTER UPDATE ON autnumrecord
BEGIN
  INSERT INTO entity (type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='autnumrecord'), NEW.handle, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Autonomous System records

CREATE TABLE IF NOT EXISTS autonomoussystem (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  asn INTEGER NOT NULL UNIQUE
);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_autonomoussystem_ai
AFTER INSERT ON autonomoussystem
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='autonomoussystem'), CAST(NEW.asn AS TEXT), '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='autonomoussystem') AND display_value=CAST(NEW.asn AS TEXT)),
    'autonomoussystem', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_autonomoussystem_au
AFTER UPDATE ON autonomoussystem
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='autonomoussystem'), CAST(NEW.asn AS TEXT), '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Contact records

CREATE TABLE IF NOT EXISTS contactrecord (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  discovered_at TEXT NOT NULL UNIQUE
);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_contactrecord_ai
AFTER INSERT ON contactrecord
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='contactrecord'), NEW.discovered_at, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='contactrecord') AND display_value=NEW.discovered_at),
    'contactrecord', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_contactrecord_au
AFTER UPDATE ON contactrecord
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='contactrecord'), NEW.discovered_at, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Domain Registration records

-- domain/fqdn/url host: normalized lowercased columns for CI uniqueness
CREATE TABLE IF NOT EXISTS domainrecord (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  unique_id  TEXT NOT NULL,
  raw_record TEXT,
  record_name TEXT NOT NULL,
  domain TEXT NOT NULL UNIQUE,
  domain_norm TEXT GENERATED ALWAYS AS (lower(domain)) STORED,
  record_status TEXT,                -- JSON array encoded (optional)
  punycode TEXT,
  extension TEXT,
  created_date TEXT,
  updated_date TEXT,
  expiration_date TEXT,
  whois_server TEXT,
  UNIQUE(domain_norm)
);
CREATE INDEX IF NOT EXISTS idx_domainrecord_name ON domainrecord(record_name);
CREATE INDEX IF NOT EXISTS idx_domainrecord_extension ON domainrecord(extension);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_domainrecord_ai
AFTER INSERT ON domainrecord
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='domainrecord'), NEW.domain_norm, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='domainrecord') AND display_value=NEW.domain_norm),
    'domainrecord', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_domainrecord_au
AFTER UPDATE ON domainrecord
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='domainrecord'), NEW.domain_norm, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Files

CREATE TABLE IF NOT EXISTS file (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  file_url TEXT NOT NULL UNIQUE,
  basename TEXT,
  file_type TEXT
);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_file_ai
AFTER INSERT ON file
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='file'), NEW.file_url, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='file') AND display_value=NEW.file_url),
    'file', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_file_au
AFTER UPDATE ON file
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='file'), NEW.file_url, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Fully Qualified Domain Names (FQDNs)

CREATE TABLE IF NOT EXISTS fqdn (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  fqdn TEXT NOT NULL,
  fqdn_norm TEXT GENERATED ALWAYS AS (lower(fqdn)) STORED,
  UNIQUE(fqdn_norm)
);

-- Fires when we insert a new fqdn row
-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_fqdn_after_insert
AFTER INSERT ON fqdn
BEGIN
  -- upsert entity
  INSERT INTO entity (type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='fqdn'), lower(NEW.fqdn), '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET
    updated_at = CURRENT_TIMESTAMP;

  -- ensure mapping
  INSERT INTO entity_ref (entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity
      WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='fqdn')
        AND display_value=lower(NEW.fqdn)),
    'fqdn',
    NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- Fires when an UPSERT takes the DO UPDATE path
-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_fqdn_after_update
AFTER UPDATE OF fqdn ON fqdn
BEGIN
  INSERT INTO entity (type_id, display_value, attrs)
  VALUES (
    (SELECT id FROM entity_type_lu WHERE name='fqdn'),
    lower(NEW.fqdn),
    '{}'
  )
  ON CONFLICT(type_id, display_value) DO UPDATE SET
    updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Funds Transfer records

CREATE TABLE IF NOT EXISTS fundstransfer (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  unique_id TEXT NOT NULL UNIQUE,
  amount REAL NOT NULL,
  reference_number TEXT,
  currency TEXT,
  transfer_method TEXT,
  exchange_date TEXT,
  exchange_rate REAL
);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_fundstransfer_ai
AFTER INSERT ON fundstransfer
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='fundstransfer'), NEW.unique_id, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='fundstransfer') AND display_value=NEW.unique_id),
    'fundstransfer', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_fundstransfer_au
AFTER UPDATE ON fundstransfer
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='fundstransfer'), NEW.unique_id, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Identifiers

CREATE TABLE IF NOT EXISTS identifier (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  id_type TEXT,
  unique_id TEXT NOT NULL UNIQUE
);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_identifier_ai
AFTER INSERT ON identifier
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='identifier'), NEW.unique_id, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='identifier') AND display_value=NEW.unique_id),
    'identifier', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_identifier_au
AFTER UPDATE ON identifier
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='identifier'), NEW.unique_id, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- IP Addresses

CREATE TABLE IF NOT EXISTS ipaddress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  ip_version TEXT NOT NULL,
  ip_address TEXT NOT NULL UNIQUE
);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_ipaddress_ai
AFTER INSERT ON ipaddress
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='ipaddress'), NEW.ip_address, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='ipaddress') AND display_value=NEW.ip_address),
    'ipaddress', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_ipaddress_au
AFTER UPDATE ON ipaddress
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='ipaddress'), NEW.ip_address, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- IP Network Registration records

CREATE TABLE IF NOT EXISTS ipnetrecord (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  record_cidr TEXT NOT NULL UNIQUE,
  record_name TEXT NOT NULL,
  ip_version TEXT NOT NULL,
  handle TEXT NOT NULL UNIQUE,
  method TEXT,
  record_status TEXT,
  created_date TEXT,
  updated_date TEXT,
  whois_server TEXT,
  parent_handle TEXT,
  start_address TEXT,
  end_address TEXT,
  country TEXT
);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_name ON ipnetrecord(record_name);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_type ON ipnetrecord(ip_version);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_ipnetrecord_ai
AFTER INSERT ON ipnetrecord
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='ipnetrecord'), NEW.handle, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='ipnetrecord') AND display_value=NEW.handle),
    'ipnetrecord', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_ipnetrecord_au
AFTER UPDATE ON ipnetrecord
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='ipnetrecord'), NEW.handle, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Locations

CREATE TABLE IF NOT EXISTS location (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  city TEXT NOT NULL,
  unit TEXT,
  street_address TEXT NOT NULL UNIQUE,
  country TEXT NOT NULL,
  building TEXT,
  province TEXT,
  locality TEXT,
  postal_code TEXT,
  street_name TEXT,
  building_number TEXT
);
CREATE INDEX IF NOT EXISTS idx_location_city ON location(city);
CREATE INDEX IF NOT EXISTS idx_location_country ON location(country);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_location_ai
AFTER INSERT ON location
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='location'), NEW.street_address, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='location') AND display_value=NEW.street_address),
    'location', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_location_au
AFTER UPDATE ON location
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='location'), NEW.street_address, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Netblocks

CREATE TABLE IF NOT EXISTS netblock (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  netblock_cidr TEXT NOT NULL UNIQUE,
  ip_version TEXT
);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_netblock_ai
AFTER INSERT ON netblock
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='netblock'), NEW.netblock_cidr, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='netblock') AND display_value=NEW.netblock_cidr),
    'netblock', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_netblock_au
AFTER UPDATE ON netblock
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='netblock'), NEW.netblock_cidr, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Organizations

CREATE TABLE IF NOT EXISTS organization (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  org_name TEXT,
  active INTEGER,
  unique_id TEXT NOT NULL UNIQUE,
  legal_name TEXT NOT NULL,
  jurisdiction TEXT,
  founding_date TEXT,
  registration_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_organization_legal_name ON organization(legal_name);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_organization_ai
AFTER INSERT ON organization
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='organization'), NEW.unique_id, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='organization') AND display_value=NEW.unique_id),
    'organization', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_organization_au
AFTER UPDATE ON organization
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='organization'), NEW.unique_id, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Persons

CREATE TABLE IF NOT EXISTS person (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  full_name TEXT,
  unique_id TEXT NOT NULL UNIQUE,
  first_name TEXT,
  family_name TEXT,
  middle_name TEXT
);
CREATE INDEX IF NOT EXISTS idx_person_full_name ON person(full_name);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_person_ai
AFTER INSERT ON person
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='person'), NEW.unique_id, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='person') AND display_value=NEW.unique_id),
    'person', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_person_au
AFTER UPDATE ON person
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='person'), NEW.unique_id, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Phone numbers

CREATE TABLE IF NOT EXISTS phone (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  raw_number TEXT NOT NULL,
  e164 TEXT NOT NULL UNIQUE,
  number_type TEXT,
  country_code INTEGER,
  country_abbrev TEXT
);
CREATE INDEX IF NOT EXISTS idx_phone_raw ON phone(raw_number);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_phone_ai
AFTER INSERT ON phone
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='phone'), NEW.e164, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='phone') AND display_value=NEW.e164),
    'phone', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_phone_au
AFTER UPDATE ON phone
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='phone'), NEW.e164, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Products

CREATE TABLE IF NOT EXISTS product (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  unique_id TEXT NOT NULL UNIQUE,
  product_name TEXT NOT NULL,
  product_type TEXT,
  category TEXT,
  product_description TEXT,
  country_of_origin TEXT
);
CREATE INDEX IF NOT EXISTS idx_product_name ON product(product_name);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_product_ai
AFTER INSERT ON product
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='product'), NEW.unique_id, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='product') AND display_value=NEW.unique_id),
    'product', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_product_au
AFTER UPDATE ON product
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='product'), NEW.unique_id, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Product Releases

CREATE TABLE IF NOT EXISTS productrelease (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  release_name TEXT NOT NULL UNIQUE,
  release_date TEXT
);
CREATE INDEX IF NOT EXISTS idx_productrelease_name ON productrelease(release_name);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_productrelease_ai
AFTER INSERT ON productrelease
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='productrelease'), NEW.release_name, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='productrelease') AND display_value=NEW.release_name),
    'productrelease', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_productrelease_au
AFTER UPDATE ON productrelease
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='productrelease'), NEW.release_name, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Services

CREATE TABLE IF NOT EXISTS service (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  unique_id TEXT NOT NULL UNIQUE,
  service_type TEXT NOT NULL,
  output_data TEXT,
  output_length INTEGER,
  attributes TEXT
);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_service_ai
AFTER INSERT ON service
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='service'), NEW.unique_id, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='service') AND display_value=NEW.unique_id),
    'service', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_service_au
AFTER UPDATE ON service
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='service'), NEW.unique_id, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- TLS Certificates

CREATE TABLE IF NOT EXISTS tlscertificate (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  is_ca INTEGER,
  tls_version INTEGER,
  key_usage TEXT,
  not_after TEXT,
  not_before TEXT,
  ext_key_usage TEXT,
  serial_number TEXT NOT NULL UNIQUE,
  subject_key_id TEXT,
  authority_key_id TEXT,
  issuer_common_name TEXT,
  signature_algorithm TEXT,
  subject_common_name TEXT NOT NULL,
  public_key_algorithm TEXT,
  crl_distribution_points TEXT
);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_tlscertificate_ai
AFTER INSERT ON tlscertificate
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='tlscertificate'), NEW.serial_number, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='tlscertificate') AND display_value=NEW.serial_number),
    'tlscertificate', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_tlscertificate_au
AFTER UPDATE ON tlscertificate
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='tlscertificate'), NEW.serial_number, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- Universal Resource Locators (URLs)

CREATE TABLE IF NOT EXISTS url (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  raw_url TEXT NOT NULL UNIQUE,
  host TEXT NOT NULL,
  host_norm TEXT GENERATED ALWAYS AS (lower(host)) STORED,
  url_path TEXT,
  port INTEGER,
  scheme TEXT
);
CREATE INDEX IF NOT EXISTS idx_url_host_norm ON url(host_norm);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_url_ai
AFTER INSERT ON url
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='url'), NEW.raw_url, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;

  INSERT INTO entity_ref(entity_id, table_name, row_id)
  VALUES (
    (SELECT entity_id FROM entity WHERE type_id=(SELECT id FROM entity_type_lu WHERE name='url') AND display_value=NEW.raw_url),
    'url', NEW.id
  )
  ON CONFLICT(entity_id, table_name, row_id) DO NOTHING;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_url_au
AFTER UPDATE ON url
BEGIN
  INSERT INTO entity(type_id, display_value, attrs)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='url'), NEW.raw_url, '{}')
  ON CONFLICT(type_id, display_value) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate Down

DROP TRIGGER IF EXISTS trg_url_au;
DROP TRIGGER IF EXISTS trg_url_ai;
DROP TABLE IF EXISTS url;

DROP TRIGGER IF EXISTS trg_tlscertificate_au;
DROP TRIGGER IF EXISTS trg_tlscertificate_ai;
DROP TABLE IF EXISTS tlscertificate;
DROP TABLE IF EXISTS service;

DROP TRIGGER IF EXISTS trg_productrelease_au;
DROP TRIGGER IF EXISTS trg_productrelease_ai;
DROP INDEX IF EXISTS idx_productrelease_name;
DROP TABLE IF EXISTS productrelease;

DROP TRIGGER IF EXISTS trg_product_au;
DROP TRIGGER IF EXISTS trg_product_ai;
DROP INDEX IF EXISTS idx_product_name;
DROP TABLE IF EXISTS product;

DROP TRIGGER IF EXISTS trg_phone_au;
DROP TRIGGER IF EXISTS trg_phone_ai;
DROP INDEX IF EXISTS idx_phone_raw;
DROP TABLE IF EXISTS phone;

DROP TRIGGER IF EXISTS trg_person_au;
DROP TRIGGER IF EXISTS trg_person_ai;
DROP INDEX IF EXISTS idx_person_full_name;
DROP TABLE IF EXISTS person;

DROP TRIGGER IF EXISTS trg_organization_au;
DROP TRIGGER IF EXISTS trg_organization_ai;
DROP INDEX IF EXISTS idx_organization_legal_name;
DROP TABLE IF EXISTS organization;

DROP TRIGGER IF EXISTS trg_location_au;
DROP TRIGGER IF EXISTS trg_location_ai;
DROP INDEX IF EXISTS idx_url_host_norm;
DROP TABLE IF EXISTS url;

DROP TRIGGER IF EXISTS trg_ipnetrecord_au;
DROP TRIGGER IF EXISTS trg_ipnetrecord_ai;
DROP INDEX IF EXISTS idx_ipnetrecord_type;
DROP INDEX IF EXISTS idx_ipnetrecord_name;
DROP TABLE IF EXISTS ipnetrecord;

DROP TRIGGER IF EXISTS trg_ipaddress_au;
DROP TRIGGER IF EXISTS trg_ipaddress_ai;
DROP TABLE IF EXISTS ipaddress;

DROP TRIGGER IF EXISTS trg_identifier_au;
DROP TRIGGER IF EXISTS trg_identifier_ai;
DROP TABLE IF EXISTS identifier;

DROP TRIGGER IF EXISTS trg_fundstransfer_au;
DROP TRIGGER IF EXISTS trg_fundstransfer_ai;
DROP TABLE IF EXISTS fundstransfer;

DROP TRIGGER IF EXISTS trg_fqdn_after_update;
DROP TRIGGER IF EXISTS trg_fqdn_after_insert;
DROP TABLE IF EXISTS fqdn;

DROP TRIGGER IF EXISTS trg_file_au;
DROP TRIGGER IF EXISTS trg_file_ai;
DROP TABLE IF EXISTS file;

DROP TRIGGER IF EXISTS trg_domainrecord_au;
DROP TRIGGER IF EXISTS trg_domainrecord_ai;
DROP INDEX IF EXISTS idx_domainrecord_extension;
DROP INDEX IF EXISTS idx_domainrecord_name;
DROP TABLE IF EXISTS domainrecord;

DROP TRIGGER IF EXISTS trg_contactrecord_au;
DROP TRIGGER IF EXISTS trg_contactrecord_ai;
DROP TABLE IF EXISTS contactrecord;

DROP TRIGGER IF EXISTS trg_autonomoussystem_au;
DROP TRIGGER IF EXISTS trg_autonomoussystem_ai;
DROP TABLE IF EXISTS autonomoussystem;

DROP TRIGGER IF EXISTS trg_autnumrecord_au;
DROP TRIGGER IF EXISTS trg_autnumrecord_ai;
DROP TABLE IF EXISTS autnumrecord;

DROP TRIGGER IF EXISTS trg_account_au;
DROP TRIGGER IF EXISTS trg_account_ai;
DROP TABLE IF EXISTS account;

DROP INDEX IF EXISTS idx_edge_tag_map;
DROP TABLE IF EXISTS edge_tag_map;

DROP INDEX IF EXISTS idx_entity_tag_map;
DROP TABLE IF EXISTS entity_tag_map;

DROP TRIGGER IF EXISTS trg_tag_au;
DROP INDEX IF EXISTS idx_tag_tt_name;
DROP TABLE IF EXISTS tag;

DROP TRIGGER IF EXISTS trg_edge_au;
DROP INDEX IF EXISTS idx_edge_to;
DROP INDEX IF EXISTS idx_edge_from;
DROP TABLE IF EXISTS edge;

DROP INDEX IF EXISTS idx_entity_ref_entity;
DROP TABLE IF EXISTS entity_ref;

DROP INDEX IF EXISTS idx_entity_display;
DROP INDEX IF EXISTS idx_entity_type;
DROP TABLE IF EXISTS entity;

DROP TABLE IF EXISTS tag_type_lu;
DROP TABLE IF EXISTS edge_type_lu;
DROP TABLE IF EXISTS entity_type_lu;