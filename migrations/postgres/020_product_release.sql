-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- ProductRelease Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.productrelease (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  release_name text NOT NULL UNIQUE,
  release_date timestamp without time zone
);
CREATE INDEX IF NOT EXISTS idx_productrelease_created_at ON public.productrelease(created_at);
CREATE INDEX IF NOT EXISTS idx_productrelease_updated_at ON public.productrelease(updated_at);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_productrelease_updated_at;
DROP INDEX IF EXISTS idx_productrelease_created_at;
DROP TABLE IF EXISTS public.productrelease;