-- +migrate Up

CREATE INDEX idx_autnum_content_handle ON entities (content->>'handle' COLLATE NOCASE) WHERE etype = 'AutnumRecord';
CREATE INDEX idx_autnum_content_number ON entities (content->>'number' COLLATE NOCASE) WHERE etype = 'AutnumRecord';
CREATE INDEX idx_autsys_content_number ON entities (content->>'number' COLLATE NOCASE) WHERE etype = 'AutonomousSystem';
CREATE INDEX idx_domainrec_content_domain ON entities (content->>'domain' COLLATE NOCASE) WHERE etype = 'DomainRecord';
CREATE INDEX idx_email_content_address ON entities (content->>'address' COLLATE NOCASE) WHERE etype = 'EmailAddress';
CREATE INDEX idx_finger_content_value ON entities (content->>'value' COLLATE NOCASE) WHERE etype = 'Fingerprint';
CREATE INDEX idx_fqdn_content_name ON entities (content->>'name' COLLATE NOCASE) WHERE etype = 'FQDN';
CREATE INDEX idx_ipaddr_content_address ON entities (content->>'address' COLLATE NOCASE) WHERE etype = 'IPAddress';
CREATE INDEX idx_ipnetrec_content_cidr ON entities (content->>'cidr' COLLATE NOCASE) WHERE etype = 'IPNetRecord';
CREATE INDEX idx_ipnetrec_content_handle ON entities (content->>'handle' COLLATE NOCASE) WHERE etype = 'IPNetRecord';
CREATE INDEX idx_netblock_content_cidr ON entities (content->>'cidr' COLLATE NOCASE) WHERE etype = 'Netblock';
CREATE INDEX idx_org_content_name ON entities (content->>'name' COLLATE NOCASE) WHERE etype = 'Organization';
CREATE INDEX idx_person_content_full_name ON entities (content->>'full_name' COLLATE NOCASE) WHERE etype = 'Person';
CREATE INDEX idx_tls_content_serial_number ON entities (content->>'serial_number' COLLATE NOCASE) WHERE etype = 'TLSCertificate';
CREATE INDEX idx_url_content_url ON entities (content->>'url') WHERE etype = 'URL';

-- +migrate Down

DROP INDEX IF EXISTS idx_url_content_url;
DROP INDEX IF EXISTS idx_tls_content_serial_number;
DROP INDEX IF EXISTS idx_person_content_full_name;
DROP INDEX IF EXISTS idx_org_content_name;
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
