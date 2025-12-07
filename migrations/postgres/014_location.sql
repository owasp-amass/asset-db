-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Location Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.location (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  city text NOT NULL,
  unit text,
  street_address text NOT NULL UNIQUE,
  country text NOT NULL,
  building text,
  province text,
  locality text,
  postal_code text,
  street_name text,
  building_number text
);
CREATE INDEX IF NOT EXISTS idx_location_created_at ON public.location(created_at);
CREATE INDEX IF NOT EXISTS idx_location_updated_at ON public.location(updated_at);
CREATE INDEX IF NOT EXISTS idx_location_building ON public.location(building);
CREATE INDEX IF NOT EXISTS idx_location_building_number ON public.location(building_number);
CREATE INDEX IF NOT EXISTS idx_location_province ON public.location(province);
CREATE INDEX IF NOT EXISTS idx_location_street_name ON public.location(street_name);
CREATE INDEX IF NOT EXISTS idx_location_unit ON public.location(unit);
CREATE INDEX IF NOT EXISTS idx_location_locality ON public.location(locality);
CREATE INDEX IF NOT EXISTS idx_location_city ON public.location(city);
CREATE INDEX IF NOT EXISTS idx_location_country ON public.location(country);
CREATE INDEX IF NOT EXISTS idx_location_postal_code ON public.location(postal_code);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_location_postal_code;
DROP INDEX IF EXISTS idx_location_country;
DROP INDEX IF EXISTS idx_location_city;
DROP INDEX IF EXISTS idx_location_locality;
DROP INDEX IF EXISTS idx_location_unit;
DROP INDEX IF EXISTS idx_location_street_name;
DROP INDEX IF EXISTS idx_location_province;
DROP INDEX IF EXISTS idx_location_building_number;
DROP INDEX IF EXISTS idx_location_building;
DROP INDEX IF EXISTS idx_location_updated_at;
DROP INDEX IF EXISTS idx_location_created_at;
DROP TABLE IF EXISTS public.location;