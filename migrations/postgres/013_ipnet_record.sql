-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- IPNetRecord Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.ipnetrecord (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  record_cidr cidr NOT NULL UNIQUE,
  record_name text NOT NULL,
  ip_version text NOT NULL,
  handle text NOT NULL UNIQUE,
  method text,
  record_status text[],
  created_date timestamp without time zone,
  updated_date timestamp without time zone,
  whois_server citext,
  parent_handle text,
  start_address inet,
  end_address inet,
  country text
);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_created_at ON public.ipnetrecord(created_at);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_updated_at ON public.ipnetrecord(updated_at);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_name ON public.ipnetrecord(record_name);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_type ON public.ipnetrecord(ip_version);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_start_address ON public.ipnetrecord(start_address);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_end_address ON public.ipnetrecord(end_address);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_whois_server ON public.ipnetrecord(whois_server);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_method ON public.ipnetrecord(method);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_country ON public.ipnetrecord(country);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_parent_handle ON public.ipnetrecord(parent_handle);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_ipnetrecord_parent_handle;
DROP INDEX IF EXISTS idx_ipnetrecord_country;
DROP INDEX IF EXISTS idx_ipnetrecord_method;
DROP INDEX IF EXISTS idx_ipnetrecord_whois_server;
DROP INDEX IF EXISTS idx_ipnetrecord_end_address;
DROP INDEX IF EXISTS idx_ipnetrecord_start_address;
DROP INDEX IF EXISTS idx_ipnetrecord_type;
DROP INDEX IF EXISTS idx_ipnetrecord_name;
DROP INDEX IF EXISTS idx_ipnetrecord_updated_at;
DROP INDEX IF EXISTS idx_ipnetrecord_created_at;
DROP TABLE IF EXISTS public.ipnetrecord;