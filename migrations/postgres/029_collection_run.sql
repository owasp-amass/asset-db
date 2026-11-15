-- +migrate Up

-- ============================================================================
-- OWASP Amass: collection runs (PostgreSQL 13+)
--
-- One row per run of a tool that collected data into the database: an
-- Amass enumeration, an import, a scanner. Any tool may record its runs
-- (repository.RunRecorder), with what it was asked to collect (scope: Open
-- Asset Model asset types and keys), when it started and finished, and how
-- it ended. A finished run tells readers what it no longer found: an asset
-- in its scope last seen before it started was not seen by it.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.collection_run (
  run_id       text PRIMARY KEY,
  created_at   timestamp without time zone NOT NULL DEFAULT now(),
  updated_at   timestamp without time zone NOT NULL DEFAULT now(),
  tool         text NOT NULL,
  tool_version text NOT NULL DEFAULT '',
  external_id  text NOT NULL DEFAULT '',
  status       text NOT NULL CHECK (status IN ('running', 'finished', 'stopped', 'failed')),
  started_at   timestamp without time zone NOT NULL,
  finished_at  timestamp without time zone,
  scope        jsonb NOT NULL DEFAULT '[]'::jsonb,
  metadata     jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_collection_run_started_at ON public.collection_run (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_collection_run_tool ON public.collection_run (tool, started_at DESC);

-- +migrate Down

DROP INDEX IF EXISTS public.idx_collection_run_tool;
DROP INDEX IF EXISTS public.idx_collection_run_started_at;
DROP TABLE IF EXISTS public.collection_run;
