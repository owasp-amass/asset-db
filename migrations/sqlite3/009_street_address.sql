-- +migrate Up

-- ============================================================================
-- OWASP Amass: the Location asset type is renamed StreetAddress (SQLite)
--
-- Open Asset Model renamed Location to StreetAddress, since a position on the
-- Earth is now its own type (GeoLocation). Stored addresses keep their entity
-- IDs, edges and properties: the table, its indexes and triggers are renamed,
-- the entity type name becomes 'streetaddress', and each entity row points at
-- the renamed table. The plain address relations become one label,
-- street_address (ContactRecord and Organization "location", Person
-- "address"); the role labels hq_address and legal_address are unchanged.
-- ============================================================================

DROP TRIGGER IF EXISTS trg_location_au;
DROP TRIGGER IF EXISTS trg_location_ai;
DROP INDEX IF EXISTS idx_location_updated_at;
DROP INDEX IF EXISTS idx_location_building;
DROP INDEX IF EXISTS idx_location_building_number;
DROP INDEX IF EXISTS idx_location_street_name;
DROP INDEX IF EXISTS idx_location_unit;
DROP INDEX IF EXISTS idx_location_city;
DROP INDEX IF EXISTS idx_location_locality;
DROP INDEX IF EXISTS idx_location_province;
DROP INDEX IF EXISTS idx_location_country;
DROP INDEX IF EXISTS idx_location_postal_code;

ALTER TABLE location RENAME TO streetaddress;
UPDATE entity_type_lu SET name = 'streetaddress' WHERE name = 'location';
UPDATE entity SET table_name = 'streetaddress' WHERE table_name = 'location';

-- the relation's label is held in the column and in the stored relation
UPDATE edge
SET label   = 'street_address',
    content = CASE WHEN json_extract(content, '$.label') IS NOT NULL
                   THEN json_set(content, '$.label', 'street_address') ELSE content END
WHERE label IN ('location', 'address')
  AND to_entity_id IN (SELECT entity_id FROM entity
                       WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'streetaddress'));

CREATE INDEX IF NOT EXISTS idx_streetaddress_updated_at ON streetaddress (updated_at);
CREATE INDEX IF NOT EXISTS idx_streetaddress_building ON streetaddress (building_norm);
CREATE INDEX IF NOT EXISTS idx_streetaddress_building_number ON streetaddress (building_number_norm);
CREATE INDEX IF NOT EXISTS idx_streetaddress_street_name ON streetaddress (street_name_norm);
CREATE INDEX IF NOT EXISTS idx_streetaddress_unit ON streetaddress (unit_norm);
CREATE INDEX IF NOT EXISTS idx_streetaddress_city ON streetaddress (city_norm);
CREATE INDEX IF NOT EXISTS idx_streetaddress_locality ON streetaddress (locality_norm);
CREATE INDEX IF NOT EXISTS idx_streetaddress_province ON streetaddress (province_norm);
CREATE INDEX IF NOT EXISTS idx_streetaddress_country ON streetaddress (country_norm);
CREATE INDEX IF NOT EXISTS idx_streetaddress_postal_code ON streetaddress (postal_code);

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_streetaddress_ai
AFTER INSERT ON streetaddress
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='streetaddress' LIMIT 1), NEW.street_address_norm, 'streetaddress', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TRIGGER IF NOT EXISTS trg_streetaddress_au
AFTER UPDATE ON streetaddress
BEGIN
  INSERT INTO entity(etype_id, natural_key, table_name, row_id)
  VALUES ((SELECT id FROM entity_type_lu WHERE name='streetaddress' LIMIT 1), NEW.street_address_norm, 'streetaddress', NEW.id)
  ON CONFLICT(etype_id, row_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;
END;
-- +migrate StatementEnd

-- +migrate Down

-- a Person's address edge was "address"; the others were "location"
UPDATE edge
SET label = CASE WHEN (SELECT t.name FROM entity f JOIN entity_type_lu t ON t.id = f.etype_id
                       WHERE f.entity_id = edge.from_entity_id) = 'person' THEN 'address' ELSE 'location' END
WHERE label = 'street_address'
  AND to_entity_id IN (SELECT entity_id FROM entity
                       WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'streetaddress'));
UPDATE edge
SET content = json_set(content, '$.label', label)
WHERE label IN ('location', 'address') AND json_extract(content, '$.label') = 'street_address';

DROP TRIGGER IF EXISTS trg_streetaddress_au;
DROP TRIGGER IF EXISTS trg_streetaddress_ai;
DROP INDEX IF EXISTS idx_streetaddress_updated_at;
DROP INDEX IF EXISTS idx_streetaddress_building;
DROP INDEX IF EXISTS idx_streetaddress_building_number;
DROP INDEX IF EXISTS idx_streetaddress_street_name;
DROP INDEX IF EXISTS idx_streetaddress_unit;
DROP INDEX IF EXISTS idx_streetaddress_city;
DROP INDEX IF EXISTS idx_streetaddress_locality;
DROP INDEX IF EXISTS idx_streetaddress_province;
DROP INDEX IF EXISTS idx_streetaddress_country;
DROP INDEX IF EXISTS idx_streetaddress_postal_code;

ALTER TABLE streetaddress RENAME TO location;
UPDATE entity_type_lu SET name = 'location' WHERE name = 'streetaddress';
UPDATE entity SET table_name = 'location' WHERE table_name = 'streetaddress';

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
