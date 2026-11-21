-- +migrate Up

-- ============================================================================
-- OWASP Amass: GeoLocation table native for asset type (SQLite)
--
-- A geographic position (WGS 84), identified by the position rounded to six
-- decimal places, "<latitude>,<longitude>". Altitude takes the latest known
-- value, and uncertainty keeps the smallest radius observed.
-- ============================================================================

INSERT OR IGNORE INTO entity_type_lu(name) VALUES ('geolocation');

CREATE TABLE IF NOT EXISTS geolocation (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  unique_id   TEXT NOT NULL UNIQUE,
  latitude    REAL NOT NULL,
  longitude   REAL NOT NULL,
  altitude    REAL,
  uncertainty REAL
);
CREATE INDEX IF NOT EXISTS idx_geolocation_updated_at ON geolocation (updated_at);
CREATE INDEX IF NOT EXISTS idx_geolocation_lat_lon ON geolocation (latitude, longitude);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_geolocation_ai
AFTER INSERT ON geolocation
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='geolocation' LIMIT 1), NEW.unique_id, 'geolocation', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_geolocation_au
AFTER UPDATE ON geolocation
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='geolocation' LIMIT 1), NEW.unique_id, 'geolocation', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate Down

DROP TRIGGER IF EXISTS trg_geolocation_au;
DROP TRIGGER IF EXISTS trg_geolocation_ai;
DROP INDEX IF EXISTS idx_geolocation_lat_lon;
DROP INDEX IF EXISTS idx_geolocation_updated_at;
DROP TABLE IF EXISTS geolocation;
DELETE FROM entity_type_lu WHERE name = 'geolocation';
