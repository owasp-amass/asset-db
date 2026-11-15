-- +migrate Up

-- ============================================================================
-- OWASP Amass: a TLS certificate is identified by its issuer and serial
-- number, not its serial number alone (SQLite).
--
-- RFC 5280 (section 4.1.2.2) makes a serial number unique per issuer only,
-- and self-signed device certificates commonly use 0 or 1: certificates of
-- unrelated hosts with the same serial were stored as one. The identity is
-- the serial number with the issuer's common name and key identifier and the
-- certificate's own key identifier, fields the Open Asset Model already has,
-- kept in cert_key, a generated column; the entity's natural key becomes the
-- same. SQLite cannot drop the old UNIQUE constraint, so the table is copied
-- (ids kept; nothing references it by foreign key) and the copy renamed in.
-- Certificates already merged stay as they are.
-- ============================================================================

DROP TRIGGER IF EXISTS trg_tlscertificate_ai;
DROP TRIGGER IF EXISTS trg_tlscertificate_au;
CREATE TABLE tlscertificate_new (
  id                       INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  serial_number            TEXT NOT NULL,
  cert_key                 TEXT GENERATED ALWAYS AS (serial_number || '|' || lower(coalesce(json_extract(attrs, '$.issuer_common_name'), ''))
    || '|' || lower(coalesce(json_extract(attrs, '$.authority_key_id'), ''))
    || '|' || lower(coalesce(json_extract(attrs, '$.subject_key_id'), ''))) STORED,
  subject_common_name      TEXT NOT NULL,
  subject_common_name_norm TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(subject_common_name)) STORED,
  attrs                    TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);

INSERT INTO tlscertificate_new (id, created_at, updated_at, serial_number, subject_common_name, attrs) SELECT id, created_at, updated_at, serial_number, subject_common_name, attrs FROM tlscertificate;
DROP TABLE tlscertificate;
ALTER TABLE tlscertificate_new RENAME TO tlscertificate;
DELETE FROM sqlite_sequence WHERE name IN ('tlscertificate', 'tlscertificate_new');
INSERT INTO sqlite_sequence (name, seq) SELECT 'tlscertificate', coalesce(max(id), 0) FROM tlscertificate;

CREATE UNIQUE INDEX tlscertificate_cert_key_uidx ON tlscertificate (cert_key);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_serial_number ON tlscertificate (serial_number);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_updated_at ON tlscertificate (updated_at);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_subject_common_name ON tlscertificate (subject_common_name_norm);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_subject_key_id
  ON tlscertificate (json_extract(attrs, '$.subject_key_id'));
CREATE INDEX IF NOT EXISTS idx_tlscertificate_authority_key_id
  ON tlscertificate (json_extract(attrs, '$.authority_key_id'));

UPDATE entity SET natural_key = (SELECT t.cert_key FROM tlscertificate t WHERE t.id = entity.row_id)
WHERE table_name = 'tlscertificate';

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_tlscertificate_ai
AFTER INSERT ON tlscertificate
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='tlscertificate' LIMIT 1), NEW.cert_key, 'tlscertificate', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET natural_key = excluded.natural_key, updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_tlscertificate_au
AFTER UPDATE ON tlscertificate
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='tlscertificate' LIMIT 1), NEW.cert_key, 'tlscertificate', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET natural_key = excluded.natural_key, updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate Down

-- Serial numbers become unique again: of the certificates sharing one, the
-- most recently seen is kept.
DROP TRIGGER IF EXISTS trg_tlscertificate_ai;
DROP TRIGGER IF EXISTS trg_tlscertificate_au;
DELETE FROM entity WHERE table_name = 'tlscertificate' AND row_id IN (
    SELECT id FROM (SELECT id, row_number() OVER (PARTITION BY serial_number ORDER BY updated_at DESC, id DESC) AS rn
                    FROM tlscertificate) WHERE rn > 1);
CREATE TABLE tlscertificate_new (
  id                       INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  serial_number            TEXT NOT NULL UNIQUE,
  subject_common_name      TEXT NOT NULL,
  subject_common_name_norm TEXT COLLATE NOCASE GENERATED ALWAYS AS (lower(subject_common_name)) STORED,
  attrs                    TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs))
);

INSERT INTO tlscertificate_new (id, created_at, updated_at, serial_number, subject_common_name, attrs)
SELECT id, created_at, updated_at, serial_number, subject_common_name, attrs FROM (
    SELECT *, row_number() OVER (PARTITION BY serial_number ORDER BY updated_at DESC, id DESC) AS rn
    FROM tlscertificate)
WHERE rn = 1;
DROP TABLE tlscertificate;
ALTER TABLE tlscertificate_new RENAME TO tlscertificate;
DELETE FROM sqlite_sequence WHERE name IN ('tlscertificate', 'tlscertificate_new');
INSERT INTO sqlite_sequence (name, seq) SELECT 'tlscertificate', coalesce(max(id), 0) FROM tlscertificate;
CREATE INDEX IF NOT EXISTS idx_tlscertificate_updated_at ON tlscertificate (updated_at);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_subject_common_name ON tlscertificate (subject_common_name_norm);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_subject_key_id
  ON tlscertificate (json_extract(attrs, '$.subject_key_id'));
CREATE INDEX IF NOT EXISTS idx_tlscertificate_authority_key_id
  ON tlscertificate (json_extract(attrs, '$.authority_key_id'));

UPDATE entity SET natural_key = (SELECT t.serial_number FROM tlscertificate t WHERE t.id = entity.row_id)
WHERE table_name = 'tlscertificate';

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_tlscertificate_ai
AFTER INSERT ON tlscertificate
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='tlscertificate' LIMIT 1), NEW.serial_number, 'tlscertificate', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET natural_key = excluded.natural_key, updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_tlscertificate_au
AFTER UPDATE ON tlscertificate
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='tlscertificate' LIMIT 1), NEW.serial_number, 'tlscertificate', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET natural_key = excluded.natural_key, updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd
