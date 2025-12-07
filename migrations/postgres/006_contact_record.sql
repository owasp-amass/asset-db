-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- ContactRecord Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.contactrecord (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  discovered_at text NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_contactrecord_created_at ON public.contactrecord(created_at);
CREATE INDEX IF NOT EXISTS idx_contactrecord_updated_at ON public.contactrecord(updated_at);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_contactrecord_updated_at;
DROP INDEX IF EXISTS idx_contactrecord_created_at;
DROP TABLE IF EXISTS public.contactrecord;