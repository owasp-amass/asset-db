-- +migrate Up

-- ============================================================================
-- OWASP Amass: index for repository.ValueFinder contains-searches over a
-- service's response headers (redirects into an organization's names).
-- ============================================================================

CREATE INDEX IF NOT EXISTS trgm_service_attributes
  ON public.service USING gin (lower(attrs->>'attributes') gin_trgm_ops);

-- +migrate Down

DROP INDEX IF EXISTS trgm_service_attributes;
