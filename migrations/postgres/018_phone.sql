-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Phone Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.phone (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  raw_number text NOT NULL,
  e164 text NOT NULL UNIQUE,
  number_type text,
  country_code integer,
  country_abbrev text
);
CREATE INDEX IF NOT EXISTS idx_phone_created_at ON public.phone(created_at);
CREATE INDEX IF NOT EXISTS idx_phone_updated_at ON public.phone(updated_at);
CREATE INDEX IF NOT EXISTS idx_phone_raw ON public.phone(raw_number);
CREATE INDEX IF NOT EXISTS idx_phone_number_type ON public.phone(number_type);
CREATE INDEX IF NOT EXISTS idx_phone_country_code ON public.phone(country_code);
CREATE INDEX IF NOT EXISTS idx_phone_country_abbrev ON public.phone(country_abbrev);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_phone_country_abbrev;
DROP INDEX IF EXISTS idx_phone_country_code;
DROP INDEX IF EXISTS idx_phone_number_type;
DROP INDEX IF EXISTS idx_phone_raw;
DROP INDEX IF EXISTS idx_phone_updated_at;
DROP INDEX IF EXISTS idx_phone_created_at;
DROP TABLE IF EXISTS public.phone;