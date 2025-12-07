-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- File Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.file (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  file_url text NOT NULL UNIQUE,
  basename text,
  file_type text
);
CREATE INDEX IF NOT EXISTS idx_file_created_at ON public.file(created_at);
CREATE INDEX IF NOT EXISTS idx_file_updated_at ON public.file(updated_at);
CREATE INDEX IF NOT EXISTS idx_file_basename ON public.file(basename);
CREATE INDEX IF NOT EXISTS idx_file_file_type ON public.file(file_type);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_file_file_type;
DROP INDEX IF EXISTS idx_file_basename;
DROP INDEX IF EXISTS idx_file_updated_at;
DROP INDEX IF EXISTS idx_file_created_at;
DROP TABLE IF EXISTS public.file;