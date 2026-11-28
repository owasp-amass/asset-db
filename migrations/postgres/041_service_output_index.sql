-- +migrate Up

-- ============================================================================
-- OWASP Amass: index for repository.ValueFinder contains-searches over the
-- text a service answered with (pages and banners that name an
-- organization). Without it each search reads every service's output.
-- ============================================================================

CREATE INDEX IF NOT EXISTS trgm_service_output
  ON public.service USING gin (lower(attrs->>'output') gin_trgm_ops);

-- +migrate Down

DROP INDEX IF EXISTS public.trgm_service_output;
