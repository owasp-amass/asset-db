-- +migrate Up

-- ============================================================================
-- OWASP Amass: indexes for repository.ValueFinder (PostgreSQL 13+)
-- Evidence correlation: certificates sharing a key identifier, and
-- contains-searches over DNS record tag values (SPF and DMARC references).
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_tlscertificate_subject_key_id
  ON public.tlscertificate ((attrs->>'subject_key_id'));
CREATE INDEX IF NOT EXISTS idx_tlscertificate_authority_key_id
  ON public.tlscertificate ((attrs->>'authority_key_id'));
CREATE INDEX IF NOT EXISTS trgm_entity_tag_dns_record_value
  ON public.entity_tag USING gin (lower(property_value) gin_trgm_ops)
  WHERE property_name = 'dns_record';

-- +migrate Down

DROP INDEX IF EXISTS trgm_entity_tag_dns_record_value;
DROP INDEX IF EXISTS idx_tlscertificate_authority_key_id;
DROP INDEX IF EXISTS idx_tlscertificate_subject_key_id;
