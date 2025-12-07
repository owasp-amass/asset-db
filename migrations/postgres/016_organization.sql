-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Organization Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.organization (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  org_name text,
  active boolean,
  unique_id text NOT NULL UNIQUE,
  legal_name text NOT NULL,
  jurisdiction text,
  founding_date timestamp without time zone,
  registration_id text
);
CREATE INDEX IF NOT EXISTS idx_organization_created_at ON public.organization(created_at);
CREATE INDEX IF NOT EXISTS idx_organization_updated_at ON public.organization(updated_at);
CREATE INDEX IF NOT EXISTS idx_organization_org_name ON public.organization(org_name);
CREATE INDEX IF NOT EXISTS idx_organization_legal_name ON public.organization(legal_name);
CREATE INDEX IF NOT EXISTS idx_organization_jurisdiction ON public.organization(jurisdiction);
CREATE INDEX IF NOT EXISTS idx_organization_registration_id ON public.organization(registration_id);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_organization_registration_id;
DROP INDEX IF EXISTS idx_organization_jurisdiction;
DROP INDEX IF EXISTS idx_organization_legal_name;
DROP INDEX IF EXISTS idx_organization_org_name;
DROP INDEX IF EXISTS idx_organization_updated_at;
DROP INDEX IF EXISTS idx_organization_created_at;
DROP TABLE IF EXISTS public.organization;