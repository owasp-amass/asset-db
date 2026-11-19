-- +migrate Up

-- ============================================================================
-- OWASP Amass: trigram indexes for repository.ValueFinder contains-searches
-- over an organization's identifier values (org-name / legal-name aliases) and
-- its URLs (service redirects into an organization's names). These values are
-- promoted out of attrs into dedicated columns (identifier.id_value,
-- url.raw_url), so the searches query the column; these indexes back the
-- case-insensitive contains match. Mirrors the trigram indexes in 024 (DNS
-- record tag values) and 025 (service response headers).
-- ============================================================================

CREATE INDEX IF NOT EXISTS trgm_identifier_id_value
  ON public.identifier USING gin (lower(id_value) gin_trgm_ops);
CREATE INDEX IF NOT EXISTS trgm_url_raw_url
  ON public.url USING gin (lower(raw_url) gin_trgm_ops);

-- +migrate Down

DROP INDEX IF EXISTS trgm_url_raw_url;
DROP INDEX IF EXISTS trgm_identifier_id_value;
