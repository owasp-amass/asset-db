-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- DomainRecord Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.domainrecord (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  raw_record text,
  record_name text NOT NULL,
  domain citext NOT NULL UNIQUE,
  record_status text[],
  punycode text,
  extension text,
  created_date timestamp without time zone,
  updated_date timestamp without time zone,
  expiration_date timestamp without time zone,
  whois_server citext,
  object_id text
);
CREATE INDEX IF NOT EXISTS idx_domainrecord_created_at ON public.domainrecord(created_at);
CREATE INDEX IF NOT EXISTS idx_domainrecord_updated_at ON public.domainrecord(updated_at);
CREATE INDEX IF NOT EXISTS idx_domainrecord_name ON public.domainrecord(record_name);
CREATE INDEX IF NOT EXISTS idx_domainrecord_extension ON public.domainrecord(extension);
CREATE INDEX IF NOT EXISTS idx_domainrecord_punycode ON public.domainrecord(punycode);
CREATE INDEX IF NOT EXISTS idx_domainrecord_whois_server ON public.domainrecord(whois_server);
CREATE INDEX IF NOT EXISTS idx_domainrecord_object_id ON public.domainrecord(object_id);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_domainrecord_object_id;
DROP INDEX IF EXISTS idx_domainrecord_whois_server;
DROP INDEX IF EXISTS idx_domainrecord_punycode;
DROP INDEX IF EXISTS idx_domainrecord_extension;
DROP INDEX IF EXISTS idx_domainrecord_record_name;
DROP INDEX IF EXISTS idx_domainrecord_updated_at;
DROP INDEX IF EXISTS idx_domainrecord_created_at;
DROP TABLE IF EXISTS public.domainrecord;