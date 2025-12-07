-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Person Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.person (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  full_name text,
  unique_id text NOT NULL UNIQUE,
  first_name text,
  family_name text,
  middle_name text
);
CREATE INDEX IF NOT EXISTS idx_person_created_at ON public.person(created_at);
CREATE INDEX IF NOT EXISTS idx_person_updated_at ON public.person(updated_at);
CREATE INDEX IF NOT EXISTS idx_person_full_name ON public.person(full_name);
CREATE INDEX IF NOT EXISTS idx_person_first_name ON public.person(first_name);
CREATE INDEX IF NOT EXISTS idx_person_family_name ON public.person(family_name);
CREATE INDEX IF NOT EXISTS idx_person_middle_name ON public.person(middle_name);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_person_middle_name;
DROP INDEX IF EXISTS idx_person_family_name;
DROP INDEX IF EXISTS idx_person_first_name;
DROP INDEX IF EXISTS idx_person_full_name;
DROP INDEX IF EXISTS idx_person_updated_at;
DROP INDEX IF EXISTS idx_person_created_at;
DROP TABLE IF EXISTS public.person;