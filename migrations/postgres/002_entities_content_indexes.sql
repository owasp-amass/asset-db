-- +migrate Up

-- Assumes the pg_trgm extension is created in the database
CREATE UNIQUE INDEX idx_account_content_unique_id ON entities USING gin ((content->>'unique_id') gin_trgm_ops) WHERE etype = 'Account';
CREATE UNIQUE INDEX idx_autnum_content_handle ON entities USING gin ((content->>'handle') gin_trgm_ops) WHERE etype = 'AutnumRecord';
CREATE INDEX idx_autnum_content_number ON entities USING gin ((content->>'number') gin_trgm_ops) WHERE etype = 'AutnumRecord';
CREATE UNIQUE INDEX idx_autsys_content_number ON entities USING gin ((content->>'number') gin_trgm_ops) WHERE etype = 'AutonomousSystem';
CREATE UNIQUE INDEX idx_contact_record_content_discovered_at ON entities USING gin ((content->>'discovered_at') gin_trgm_ops) WHERE etype = 'ContactRecord';
CREATE UNIQUE INDEX idx_domainrec_content_domain ON entities USING gin ((content->>'domain') gin_trgm_ops) WHERE etype = 'DomainRecord';
CREATE UNIQUE INDEX idx_file_content_url ON entities USING gin ((content->>'url') gin_trgm_ops) WHERE etype = 'File';
CREATE UNIQUE INDEX idx_fqdn_content_name ON entities USING gin ((content->>'name') gin_trgm_ops) WHERE etype = 'FQDN';
CREATE UNIQUE INDEX idx_funds_transfer_content_unique_id ON entities USING gin ((content->>'unique_id') gin_trgm_ops) WHERE etype = 'FundsTransfer';
CREATE UNIQUE INDEX idx_identifier_content_unique_id ON entities USING gin ((content->>'unique_id') gin_trgm_ops) WHERE etype = 'Identifier';
CREATE UNIQUE INDEX idx_ipaddr_content_address ON entities USING gin ((content->>'address') gin_trgm_ops) WHERE etype = 'IPAddress';
CREATE INDEX idx_ipnetrec_content_cidr ON entities USING gin ((content->>'cidr') gin_trgm_ops) WHERE etype = 'IPNetRecord';
CREATE UNIQUE INDEX idx_ipnetrec_content_handle ON entities USING gin ((content->>'handle') gin_trgm_ops) WHERE etype = 'IPNetRecord';
CREATE UNIQUE INDEX idx_location_content_address ON entities USING gin ((content->>'address') gin_trgm_ops) WHERE etype = 'Location';
CREATE UNIQUE INDEX idx_netblock_content_cidr ON entities USING gin ((content->>'cidr') gin_trgm_ops) WHERE etype = 'Netblock';
CREATE UNIQUE INDEX idx_org_content_unique_id ON entities USING gin ((content->>'unique_id') gin_trgm_ops) WHERE etype = 'Organization';
CREATE INDEX idx_org_content_name ON entities USING gin ((content->>'name') gin_trgm_ops) WHERE etype = 'Organization';
CREATE UNIQUE INDEX idx_person_content_unique_id ON entities USING gin ((content->>'unique_id') gin_trgm_ops) WHERE etype = 'Person';
CREATE INDEX idx_person_content_full_name ON entities USING gin ((content->>'full_name') gin_trgm_ops) WHERE etype = 'Person';
CREATE UNIQUE INDEX idx_phone_content_e164 ON entities USING gin ((content->>'e164') gin_trgm_ops) WHERE etype = 'Phone';
CREATE UNIQUE INDEX idx_phone_content_raw ON entities USING gin ((content->>'raw') gin_trgm_ops) WHERE etype = 'Phone';
CREATE UNIQUE INDEX idx_product_content_unique_id ON entities USING gin ((content->>'unique_id') gin_trgm_ops) WHERE etype = 'Product';
CREATE INDEX idx_product_content_product_name ON entities USING gin ((content->>'product_name') gin_trgm_ops) WHERE etype = 'Product';
CREATE UNIQUE INDEX idx_product_release_content_name ON entities USING gin ((content->>'name') gin_trgm_ops) WHERE etype = 'ProductRelease';
CREATE UNIQUE INDEX idx_service_content_unique_id ON entities USING gin ((content->>'unique_id') gin_trgm_ops) WHERE etype = 'Service';
CREATE UNIQUE INDEX idx_tls_content_serial_number ON entities USING gin ((content->>'serial_number') gin_trgm_ops) WHERE etype = 'TLSCertificate';
CREATE UNIQUE INDEX idx_url_content_url ON entities USING gin ((content->>'url') gin_trgm_ops) WHERE etype = 'URL';

-- +migrate Down

DROP INDEX IF EXISTS idx_url_content_url;
DROP INDEX IF EXISTS idx_tls_content_serial_number;
DROP INDEX IF EXISTS idx_service_content_unique_id;
DROP INDEX IF EXISTS idx_product_release_content_name;
DROP INDEX IF EXISTS idx_product_content_product_name;
DROP INDEX IF EXISTS idx_product_content_unique_id;
DROP INDEX IF EXISTS idx_phone_content_raw;
DROP INDEX IF EXISTS idx_phone_content_e164;
DROP INDEX IF EXISTS idx_person_content_full_name;
DROP INDEX IF EXISTS idx_person_content_unique_id;
DROP INDEX IF EXISTS idx_org_content_name;
DROP INDEX IF EXISTS idx_org_content_unique_id;
DROP INDEX IF EXISTS idx_netblock_content_cidr;
DROP INDEX IF EXISTS idx_location_content_address;
DROP INDEX IF EXISTS idx_ipnetrec_content_handle;
DROP INDEX IF EXISTS idx_ipnetrec_content_cidr;
DROP INDEX IF EXISTS idx_ipaddr_content_address;
DROP INDEX IF EXISTS idx_identifier_content_unique_id;
DROP INDEX IF EXISTS idx_funds_transfer_content_unique_id;
DROP INDEX IF EXISTS idx_fqdn_content_name;
DROP INDEX IF EXISTS idx_file_content_url;
DROP INDEX IF EXISTS idx_domainrec_content_domain;
DROP INDEX IF EXISTS idx_contact_record_content_discovered_at;
DROP INDEX IF EXISTS idx_autsys_content_number;
DROP INDEX IF EXISTS idx_autnum_content_number;
DROP INDEX IF EXISTS idx_autnum_content_handle;
DROP INDEX IF EXISTS idx_account_content_unique_id;