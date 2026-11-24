-- +migrate Up
CREATE INDEX IF NOT EXISTS idx_ip_content_address ON assets USING gin ((content->>'address') gin_trgm_ops) WHERE type = 'IPAddress';
CREATE INDEX IF NOT EXISTS idx_net_content_cidr ON assets USING gin ((content->>'cidr') gin_trgm_ops) WHERE type = 'Netblock';
CREATE INDEX IF NOT EXISTS idx_rir_content_name ON assets USING gin ((content->>'name') gin_trgm_ops) WHERE type = 'RIROrg';
CREATE INDEX IF NOT EXISTS idx_asn_content_num ON assets USING gin ((content->>'number') gin_trgm_ops) WHERE type = 'ASN';

-- +migrate Down
DROP INDEX IF EXISTS idx_ip_content_address;
DROP INDEX IF EXISTS idx_net_content_cidr;
DROP INDEX IF EXISTS idx_rir_content_name;
DROP INDEX IF EXISTS idx_asn_content_num;