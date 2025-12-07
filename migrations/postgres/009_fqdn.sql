-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- FQDN Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.fqdn (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  fqdn citext NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_fqdn_created_at ON public.fqdn(created_at);
CREATE INDEX IF NOT EXISTS idx_fqdn_updated_at ON public.fqdn(updated_at);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_fqdn_updated_at;
DROP INDEX IF EXISTS idx_fqdn_created_at;
DROP TABLE IF EXISTS public.fqdn;