-- +migrate Up

-- Assumes the pg_trgm extension is created in the database
CREATE INDEX idx_autnum_content_handle ON entities USING gin ((content->>'handle') gin_trgm_ops) WHERE etype = 'AutnumRecord';
CREATE INDEX idx_autnum_content_number ON entities USING gin ((content->>'number') gin_trgm_ops) WHERE etype = 'AutnumRecord';
CREATE INDEX idx_autsys_content_number ON entities USING gin ((content->>'number') gin_trgm_ops) WHERE etype = 'AutonomousSystem';
CREATE INDEX idx_domainrec_content_domain ON entities USING gin ((content->>'domain') gin_trgm_ops) WHERE etype = 'DomainRecord';
CREATE INDEX idx_email_content_address ON entities USING gin ((content->>'address') gin_trgm_ops) WHERE etype = 'EmailAddress';
CREATE INDEX idx_finger_content_value ON entities USING gin ((content->>'value') gin_trgm_ops) WHERE etype = 'Fingerprint';
CREATE INDEX idx_fqdn_content_name ON entities USING gin ((content->>'name') gin_trgm_ops) WHERE etype = 'FQDN';
CREATE INDEX idx_ipaddr_content_address ON entities USING gin ((content->>'address') gin_trgm_ops) WHERE etype = 'IPAddress';
CREATE INDEX idx_ipnetrec_content_cidr ON entities USING gin ((content->>'cidr') gin_trgm_ops) WHERE etype = 'IPNetRecord';
CREATE INDEX idx_ipnetrec_content_handle ON entities USING gin ((content->>'handle') gin_trgm_ops) WHERE etype = 'IPNetRecord';
CREATE INDEX idx_netblock_content_cidr ON entities USING gin ((content->>'cidr') gin_trgm_ops) WHERE etype = 'Netblock';
CREATE INDEX idx_netend_content_address ON entities USING gin ((content->>'address') gin_trgm_ops) WHERE etype = 'NetworkEndpoint';
CREATE INDEX idx_org_content_name ON entities USING gin ((content->>'name') gin_trgm_ops) WHERE etype = 'Organization';
CREATE INDEX idx_person_content_full_name ON entities USING gin ((content->>'full_name') gin_trgm_ops) WHERE etype = 'Person';
CREATE INDEX idx_sockaddr_content_address ON entities USING gin ((content->>'address') gin_trgm_ops) WHERE etype = 'SocketAddress';
CREATE INDEX idx_tls_content_serial_number ON entities USING gin ((content->>'serial_number') gin_trgm_ops) WHERE etype = 'TLSCertificate';
CREATE INDEX idx_url_content_url ON entities USING gin ((content->>'url') gin_trgm_ops) WHERE etype = 'URL';

-- +migrate Down

DROP INDEX IF EXISTS idx_url_content_url;
DROP INDEX IF EXISTS idx_tls_content_serial_number;
DROP INDEX IF EXISTS idx_sockaddr_content_address;
DROP INDEX IF EXISTS idx_person_content_full_name;
DROP INDEX IF EXISTS idx_org_content_name;
DROP INDEX IF EXISTS idx_netend_content_address;
DROP INDEX IF EXISTS idx_netblock_content_cidr;
DROP INDEX IF EXISTS idx_ipnetrec_content_handle;
DROP INDEX IF EXISTS idx_ipnetrec_content_cidr;
DROP INDEX IF EXISTS idx_ipaddr_content_address;
DROP INDEX IF EXISTS idx_fqdn_content_name;
DROP INDEX IF EXISTS idx_finger_content_value;
DROP INDEX IF EXISTS idx_email_content_address;
DROP INDEX IF EXISTS idx_domainrec_content_domain;
DROP INDEX IF EXISTS idx_autsys_content_number;
DROP INDEX IF EXISTS idx_autnum_content_handle;
DROP INDEX IF EXISTS idx_autnum_content_number;
