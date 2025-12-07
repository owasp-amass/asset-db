-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Service Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.service (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  unique_id text NOT NULL UNIQUE,
  service_type text NOT NULL,
  output_data text,
  output_length integer,
  attributes jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_service_created_at ON public.service(created_at);
CREATE INDEX IF NOT EXISTS idx_service_updated_at ON public.service(updated_at);
CREATE INDEX IF NOT EXISTS idx_service_service_type ON public.service(service_type);
CREATE INDEX IF NOT EXISTS idx_service_output_length ON public.service(output_length);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_service_output_length;
DROP INDEX IF EXISTS idx_service_service_type;
DROP INDEX IF EXISTS idx_service_updated_at;
DROP INDEX IF EXISTS idx_service_created_at;
DROP TABLE IF EXISTS public.service;