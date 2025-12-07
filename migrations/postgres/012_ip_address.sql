-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- IPAddress Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.ipaddress (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  ip_version text NOT NULL,
  ip_address inet NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_ipaddress_created_at ON public.ipaddress(created_at);
CREATE INDEX IF NOT EXISTS idx_ipaddress_updated_at ON public.ipaddress(updated_at);
CREATE INDEX IF NOT EXISTS idx_ipaddress_ip_version ON public.ipaddress(ip_version);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_ipaddress_ip_version;
DROP INDEX IF EXISTS idx_ipaddress_updated_at;
DROP INDEX IF EXISTS idx_ipaddress_created_at;
DROP TABLE IF EXISTS public.ipaddress;