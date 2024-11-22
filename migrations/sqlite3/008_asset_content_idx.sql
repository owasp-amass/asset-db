-- +migrate Up
CREATE INDEX idx_ip_content_address ON assets (content->>'address' COLLATE NOCASE) WHERE type = 'IPAddress';
CREATE INDEX idx_net_content_cidr ON assets (content->>'cidr' COLLATE NOCASE) WHERE type = 'Netblock';
CREATE INDEX idx_rir_content_name ON assets (content->>'name' COLLATE NOCASE) WHERE type = 'RIROrg';
CREATE INDEX idx_asn_content_num ON assets (content->>'number' COLLATE NOCASE) WHERE type = 'ASN';

-- +migrate Down
DROP INDEX IF EXISTS idx_ip_content_address;
DROP INDEX IF EXISTS idx_net_content_cidr;
DROP INDEX IF EXISTS idx_rir_content_name;
DROP INDEX IF EXISTS idx_asn_content_num;