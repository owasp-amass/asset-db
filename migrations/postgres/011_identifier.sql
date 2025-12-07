-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Identifier Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.identifier (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  id_type text,
  unique_id text NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_identifier_created_at ON public.identifier(created_at);
CREATE INDEX IF NOT EXISTS idx_identifier_updated_at ON public.identifier(updated_at);
CREATE INDEX IF NOT EXISTS idx_identifier_id_type ON public.identifier(id_type);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_identifier_id_type;
DROP INDEX IF EXISTS idx_identifier_updated_at;
DROP INDEX IF EXISTS idx_identifier_created_at;
DROP TABLE IF EXISTS public.identifier;