-- +migrate Up

-- ============================================================================
-- OWASP Amass: the journal and leases (PostgreSQL 13+)
--
-- journal: an append-only log the tools sharing the database coordinate
-- through (repository.JournalStore): the decisions made about its data, the
-- runs and schedules of the tools, and the work they share. Records are
-- grouped by topic, and within a topic by kind and key; their data is the
-- tool's own JSON, so a new kind of record needs no new schema. seq orders
-- the records across every writer.
--
-- lease: named work that one holder at a time may do until it expires or is
-- released (repository.LeaseStore). Times are UTC.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.journal (
  seq    bigserial PRIMARY KEY,
  topic  text NOT NULL,
  kind   text NOT NULL,
  key    text NOT NULL DEFAULT '',
  data   jsonb NOT NULL DEFAULT '{}'::jsonb,
  actor  text NOT NULL DEFAULT '',
  at     timestamp without time zone NOT NULL DEFAULT timezone('utc', now()),
  cause  bigint
);
CREATE INDEX IF NOT EXISTS idx_journal_topic_seq ON public.journal (topic, seq);
CREATE INDEX IF NOT EXISTS idx_journal_topic_key ON public.journal (topic, key, seq);

CREATE TABLE IF NOT EXISTS public.lease (
  name        text PRIMARY KEY,
  holder      text NOT NULL,
  acquired_at timestamp without time zone NOT NULL,
  expires_at  timestamp without time zone NOT NULL,
  data        jsonb NOT NULL DEFAULT '{}'::jsonb
);

-- +migrate Down

DROP TABLE IF EXISTS public.lease;
DROP INDEX IF EXISTS public.idx_journal_topic_key;
DROP INDEX IF EXISTS public.idx_journal_topic_seq;
DROP TABLE IF EXISTS public.journal;
