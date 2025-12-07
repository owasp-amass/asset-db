-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- URL Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.url (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  raw_url text NOT NULL UNIQUE,
  host citext NOT NULL,
  url_path text,
  port integer,
  scheme text
);
CREATE INDEX IF NOT EXISTS idx_url_created_at ON public.url(created_at);
CREATE INDEX IF NOT EXISTS idx_url_updated_at ON public.url(updated_at);
CREATE INDEX IF NOT EXISTS idx_url_host ON public.url(host);
CREATE INDEX IF NOT EXISTS idx_url_path ON public.url(url_path);
CREATE INDEX IF NOT EXISTS idx_url_port ON public.url(port);
CREATE INDEX IF NOT EXISTS idx_url_scheme ON public.url(scheme);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_url_scheme;
DROP INDEX IF EXISTS idx_url_port;
DROP INDEX IF EXISTS idx_url_path;
DROP INDEX IF EXISTS idx_url_host;
DROP INDEX IF EXISTS idx_url_updated_at;
DROP INDEX IF EXISTS idx_url_created_at;
DROP TABLE IF EXISTS public.url;