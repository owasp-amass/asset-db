-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Netblock Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.netblock (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  netblock_cidr cidr NOT NULL UNIQUE,
  ip_version text NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_netblock_created_at ON public.netblock(created_at);
CREATE INDEX IF NOT EXISTS idx_netblock_updated_at ON public.netblock(updated_at);
CREATE INDEX IF NOT EXISTS idx_netblock_ip_version ON public.netblock(ip_version);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_netblock_ip_version;
DROP INDEX IF EXISTS idx_netblock_updated_at;
DROP INDEX IF EXISTS idx_netblock_created_at;
DROP TABLE IF EXISTS public.netblock;