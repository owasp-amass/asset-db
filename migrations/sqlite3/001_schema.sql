-- +migrate Up

-- ============================================================================
-- OWASP Amass — High-performance schema for SQLite (3.38+ recommended)
-- - Uses JSON1 (json_valid/json_extract/json_patch)
-- - Lowercased “normalized” columns for case-insensitive uniqueness
-- - Native UPSERT via INSERT ... ON CONFLICT
-- - No partitions (SQLite), but compact indexes
-- ============================================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;         -- tweak to FULL for extra durability
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 268435456;        -- 256 MiB map if available
PRAGMA page_size = 4096;
PRAGMA cache_size = -1048576;        -- ~1 GiB cache (negative = KiB units)

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

-- Seed common types (extend as needed)
INSERT OR IGNORE INTO entity_type_lu(name) VALUES
 ('account'),('autnumrecord'),('autonomoussystem'),('contactrecord'),
 ('domainrecord'),('file'),('fqdn'),('fundstransfer'),('identifier'),
 ('ipaddress'),('ipnetrecord'),('location'),('netblock'),('organization'),
 ('person'),('phone'),('product'),('productrelease'),('service'),
 ('tlscertificate'),('url');

INSERT OR IGNORE INTO edge_type_lu(name) VALUES
 ('basicdnsrelation'),('portrelation'),('prefdnsrelation'),('simplerelation'),('srvdnsrelation');

-- -----------------------------
-- Core entity & mapping
-- -----------------------------
CREATE TABLE IF NOT EXISTS entities (
  entity_id     INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  type_id       INTEGER NOT NULL REFERENCES entity_type_lu(id),
  display_value TEXT NOT NULL,
  attrs         TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs)),
  UNIQUE (type_id, display_value)
);
CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(type_id);

CREATE TABLE IF NOT EXISTS entity_ref (
  ref_id     INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  entity_id  INTEGER NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE,
  table_name TEXT NOT NULL,
  row_id     INTEGER NOT NULL,
  UNIQUE (table_name, row_id),
  UNIQUE (entity_id, table_name, row_id)
);
CREATE INDEX IF NOT EXISTS idx_entity_ref_entity ON entity_ref(entity_id);
CREATE INDEX IF NOT EXISTS idx_entity_ref_table_row ON entity_ref(table_name, row_id);

-- -----------------------------
-- Asset tables (with normalized columns)
-- -----------------------------
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

CREATE TABLE IF NOT EXISTS autonomoussystem (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  asn INTEGER NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS contactrecord (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  discovered_at TEXT NOT NULL UNIQUE
);

-- domain/fqdn/url host: normalized lowercased columns for CI uniqueness
CREATE TABLE IF NOT EXISTS domainrecord (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  unique_id  TEXT,
  raw_record TEXT,
  record_name TEXT NOT NULL,
  domain TEXT NOT NULL,
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

CREATE TABLE IF NOT EXISTS file (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  file_url TEXT NOT NULL UNIQUE,
  basename TEXT,
  file_type TEXT
);

CREATE TABLE IF NOT EXISTS fqdn (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  fqdn TEXT NOT NULL,
  fqdn_norm TEXT GENERATED ALWAYS AS (lower(fqdn)) STORED,
  UNIQUE(fqdn_norm)
);

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

CREATE TABLE IF NOT EXISTS identifier (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  id_type TEXT,
  unique_id TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS ipaddress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  ip_version TEXT NOT NULL,
  ip_address TEXT NOT NULL UNIQUE
);

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

CREATE TABLE IF NOT EXISTS netblock (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  netblock_cidr TEXT NOT NULL UNIQUE,
  ip_version TEXT
);

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

CREATE TABLE IF NOT EXISTS productrelease (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  release_name TEXT NOT NULL UNIQUE,
  release_date TEXT
);
CREATE INDEX IF NOT EXISTS idx_productrelease_name ON productrelease(release_name);

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

-- -----------------------------
-- Graph edges & tags
-- -----------------------------
CREATE TABLE IF NOT EXISTS edges (
  edge_id       INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  etype_id      INTEGER NOT NULL REFERENCES edge_type_lu(id),
  content       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(content)),
  from_entity_id INTEGER NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE,
  to_entity_id   INTEGER NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE,
  UNIQUE (etype_id, from_entity_id, to_entity_id),
  CHECK (from_entity_id <> to_entity_id)
);
CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_entity_id, etype_id, to_entity_id);
CREATE INDEX IF NOT EXISTS idx_edges_to   ON edges(to_entity_id, etype_id, from_entity_id);

CREATE TABLE IF NOT EXISTS tags (
  tag_id     INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  namespace  TEXT DEFAULT 'default',
  name       TEXT NOT NULL,
  value      TEXT,
  meta       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(meta)),
  UNIQUE (namespace, name, coalesce(value,'∅'))
);
CREATE INDEX IF NOT EXISTS idx_tags_ns_name ON tags(namespace, name);

CREATE TABLE IF NOT EXISTS entity_tag_map (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  entity_id  INTEGER NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE,
  tag_id     INTEGER NOT NULL REFERENCES tags(tag_id) ON DELETE CASCADE,
  details    TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details)),
  UNIQUE (entity_id, tag_id)
);
CREATE INDEX IF NOT EXISTS idx_entity_tag_map ON entity_tag_map(entity_id, tag_id);

CREATE TABLE IF NOT EXISTS edge_tag_map (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  edge_id    INTEGER NOT NULL REFERENCES edges(edge_id) ON DELETE CASCADE,
  tag_id     INTEGER NOT NULL REFERENCES tags(tag_id) ON DELETE CASCADE,
  details    TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details)),
  UNIQUE (edge_id, tag_id)
);
CREATE INDEX IF NOT EXISTS idx_edge_tag_map ON edge_tag_map(edge_id, tag_id);


-- +migrate Down

DROP INDEX IF EXISTS idx_edge_tag_map;
DROP TABLE IF EXISTS edge_tag_map;

DROP INDEX IF EXISTS idx_entity_tag_map;
DROP TABLE IF EXISTS entity_tag_map;

DROP INDEX IF EXISTS idx_tags_ns_name;
DROP TABLE IF EXISTS tags;

DROP INDEX IF EXISTS idx_edges_to;
DROP INDEX IF EXISTS idx_edges_from;
DROP TABLE IF EXISTS edges;

DROP INDEX IF EXISTS idx_url_host_norm;
DROP TABLE IF EXISTS url;

DROP TABLE IF EXISTS tlscertificate;
DROP TABLE IF EXISTS service;

DROP INDEX IF EXISTS idx_productrelease_name;
DROP TABLE IF EXISTS productrelease;

DROP INDEX IF EXISTS idx_product_name;
DROP TABLE IF EXISTS product;

DROP INDEX IF EXISTS idx_phone_raw;
DROP TABLE IF EXISTS phone;

DROP INDEX IF EXISTS idx_person_full_name;
DROP TABLE IF EXISTS person;

DROP INDEX IF EXISTS idx_organization_legal_name;
DROP TABLE IF EXISTS organization;

DROP INDEX IF EXISTS idx_ipnetrecord_type;
DROP INDEX IF EXISTS idx_ipnetrecord_name;
DROP TABLE IF EXISTS ipnetrecord;

DROP TABLE IF EXISTS ipaddress;
DROP TABLE IF EXISTS identifier;
DROP TABLE IF EXISTS fundstransfer;
DROP TABLE IF EXISTS fqdn;
DROP TABLE IF EXISTS file;

DROP INDEX IF EXISTS idx_domainrecord_extension;
DROP INDEX IF EXISTS idx_domainrecord_name;
DROP TABLE IF EXISTS domainrecord;

DROP TABLE IF EXISTS contactrecord;
DROP TABLE IF EXISTS autonomoussystem;
DROP TABLE IF EXISTS autnumrecord;
DROP TABLE IF EXISTS account;

DROP INDEX IF EXISTS idx_entity_ref_table_row;
DROP INDEX IF EXISTS idx_entity_ref_entity;
DROP TABLE IF EXISTS entity_ref;

DROP INDEX IF EXISTS idx_entities_type;
DROP TABLE IF EXISTS entities;

DROP TABLE IF EXISTS edge_type_lu;
DROP TABLE IF EXISTS entity_type_lu;