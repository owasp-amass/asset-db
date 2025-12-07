-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- TLSCertificate Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.tlscertificate (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  is_ca boolean,
  tls_version integer,
  key_usage text,
  not_after timestamp without time zone,
  not_before timestamp without time zone,
  ext_key_usage text,
  serial_number text NOT NULL UNIQUE,
  subject_key_id text,
  authority_key_id text,
  issuer_common_name text,
  signature_algorithm text,
  subject_common_name text NOT NULL,
  public_key_algorithm text,
  crl_distribution_points text
);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_created_at ON public.tlscertificate(created_at);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_updated_at ON public.tlscertificate(updated_at);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_tls_version ON public.tlscertificate(tls_version);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_subject_common_name ON public.tlscertificate(subject_common_name);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_issuer_common_name ON public.tlscertificate(issuer_common_name);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_signature_algorithm ON public.tlscertificate(signature_algorithm);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_public_key_algorithm ON public.tlscertificate(public_key_algorithm);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_tlscertificate_public_key_algorithm;
DROP INDEX IF EXISTS idx_tlscertificate_signature_algorithm;
DROP INDEX IF EXISTS idx_tlscertificate_issuer_common_name;
DROP INDEX IF EXISTS idx_tlscertificate_subject_common_name;
DROP INDEX IF EXISTS idx_tlscertificate_tls_version;
DROP INDEX IF EXISTS idx_tlscertificate_updated_at;
DROP INDEX IF EXISTS idx_tlscertificate_created_at;
DROP TABLE IF EXISTS public.tlscertificate;