-- +migrate Up

-- Assumes the pg_trgm extension is created in the database
-- Index the `address` field of the `content` jsonb when type is `NetworkEndpoint`
CREATE INDEX idx_netend_content_address ON assets USING gin ((content->>'address') gin_trgm_ops) WHERE type = 'NetworkEndpoint';

-- Index the `address` field of the `content` jsonb when type is `IPAddress`
CREATE INDEX idx_ipaddr_content_address ON assets USING gin ((content->>'address') gin_trgm_ops) WHERE type = 'IPAddress';

-- Index the `cidr` field of the `content` jsonb when type is `Netblock`
CREATE INDEX idx_netblock_content_cidr ON assets USING gin ((content->>'cidr') gin_trgm_ops) WHERE type = 'Netblock';

-- Index the `number` field of the `content` jsonb when type is `AutonomousSystem`
CREATE INDEX idx_autsys_content_number ON assets USING gin ((content->>'number') gin_trgm_ops) WHERE type = 'AutonomousSystem';

-- Index the `address` field of the `content` jsonb when type is `SocketAddress`
CREATE INDEX idx_sockaddr_content_address ON assets USING gin ((content->>'address') gin_trgm_ops) WHERE type = 'SocketAddress';

-- Index the `name` field of the `content` jsonb when type is `Organization`
CREATE INDEX idx_org_content_name ON assets USING gin ((content->>'name') gin_trgm_ops) WHERE type = 'Organization';

-- Index the `value` field of the `content` jsonb when type is `Fingerprint`
CREATE INDEX idx_finger_content_value ON assets USING gin ((content->>'value') gin_trgm_ops) WHERE type = 'Fingerprint';

-- Index the `serial_number` field of the `content` jsonb when type is `TLSCertificate`
CREATE INDEX idx_tls_content_serial_number ON assets USING gin ((content->>'serial_number') gin_trgm_ops) WHERE type = 'TLSCertificate';

-- Index the `url` field of the `content` jsonb when type is `URL`
CREATE INDEX idx_url_content_url ON assets USING gin ((content->>'url') gin_trgm_ops) WHERE type = 'URL';

-- Index the `address` field of the `content` jsonb when type is `EmailAddress`
CREATE INDEX idx_email_content_address ON assets USING gin ((content->>'address') gin_trgm_ops) WHERE type = 'EmailAddress';

-- Index the `full_name` field of the `content` jsonb when type is `Person`
CREATE INDEX idx_person_content_full_name ON assets USING gin ((content->>'full_name') gin_trgm_ops) WHERE type = 'Person';

-- Index the `handle` field of the `content` jsonb when type is `AutnumRecord`
CREATE INDEX idx_autnum_content_handle ON assets USING gin ((content->>'handle') gin_trgm_ops) WHERE type = 'AutnumRecord';

-- Index the `number` field of the `content` jsonb when type is `AutnumRecord`
CREATE INDEX idx_autnum_content_number ON assets USING gin ((content->>'number') gin_trgm_ops) WHERE type = 'AutnumRecord';

-- Index the `domain` field of the `content` jsonb when type is `DomainRecord`
CREATE INDEX idx_domainrec_content_domain ON assets USING gin ((content->>'domain') gin_trgm_ops) WHERE type = 'DomainRecord';

-- Index the `handle` field of the `content` jsonb when type is `IPNetRecord`
CREATE INDEX idx_ipnetrec_content_handle ON assets USING gin ((content->>'handle') gin_trgm_ops) WHERE type = 'IPNetRecord';

-- Index the `cidr` field of the `content` jsonb when type is `IPNetRecord`
CREATE INDEX idx_ipnetrec_content_cidr ON assets USING gin ((content->>'cidr') gin_trgm_ops) WHERE type = 'IPNetRecord';

-- Index the `name` field of the `content` jsonb when type is `Source`
CREATE INDEX idx_source_content_name ON assets USING gin ((content->>'name') gin_trgm_ops) WHERE type = 'Source';


-- +migrate Down

-- drop all the indexes we just created
DROP INDEX idx_netend_content_address;
DROP INDEX idx_ipaddr_content_address;
DROP INDEX idx_netblock_content_cidr;
DROP INDEX idx_autsys_content_number;
DROP INDEX idx_sockaddr_content_address;
DROP INDEX idx_org_content_name;
DROP INDEX idx_finger_content_value;
DROP INDEX idx_tls_content_serial_number;
DROP INDEX idx_url_content_url;
DROP INDEX idx_email_content_address;
DROP INDEX idx_person_content_full_name;
DROP INDEX idx_autnum_content_handle;
DROP INDEX idx_autnum_content_number;
DROP INDEX idx_domainrec_content_domain;
DROP INDEX idx_ipnetrec_content_handle;
DROP INDEX idx_ipnetrec_content_cidr;
DROP INDEX idx_source_content_name;