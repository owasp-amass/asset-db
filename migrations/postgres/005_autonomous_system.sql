-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- AutonomousSystem Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.autonomoussystem (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  asn integer NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_autonomoussystem_created_at ON public.autonomoussystem(created_at);
CREATE INDEX IF NOT EXISTS idx_autonomoussystem_updated_at ON public.autonomoussystem(updated_at);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_autonomoussystem_updated_at;
DROP INDEX IF EXISTS idx_autonomoussystem_created_at;
DROP TABLE IF EXISTS public.autonomoussystem;