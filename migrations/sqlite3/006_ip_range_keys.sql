-- +migrate Up

-- ============================================================================
-- OWASP Amass: IP range searches (SQLite)
-- SQLite stores addresses as text, which does not sort as numbers, so each
-- address and netblock also has 16-byte keys (an IPv4 address as its
-- IPv4-mapped IPv6 form) that compare as the addresses do. asset-db writes
-- them, and fills in rows written without them (by other tools, or before
-- this migration) when it opens the database.
-- ============================================================================

ALTER TABLE ipaddress ADD COLUMN ip_key BLOB;
CREATE INDEX IF NOT EXISTS idx_ipaddress_ip_key ON ipaddress (ip_key);
ALTER TABLE netblock ADD COLUMN first_key BLOB;
ALTER TABLE netblock ADD COLUMN last_key BLOB;
CREATE INDEX IF NOT EXISTS idx_netblock_keys ON netblock (first_key, last_key);

-- +migrate Down

DROP INDEX IF EXISTS idx_netblock_keys;
ALTER TABLE netblock DROP COLUMN last_key;
ALTER TABLE netblock DROP COLUMN first_key;
DROP INDEX IF EXISTS idx_ipaddress_ip_key;
ALTER TABLE ipaddress DROP COLUMN ip_key;
