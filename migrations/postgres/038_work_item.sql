-- +migrate Up

-- ============================================================================
-- OWASP Amass: work queues (PostgreSQL 13+)
--
-- work_item: the items of work the tools sharing the database divide among
-- themselves (repository.WorkQueue), such as the assets an enumeration still
-- has to process. Each item is named by its key, unique in its queue, and
-- has a kind (an asset type) that claims select by. state is 0 queued,
-- 1 leased to owner until lease_until (no time: until acked or released),
-- or 2 done. id keeps the order items were first queued in. Times are UTC.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.work_item (
  id          bigserial PRIMARY KEY,
  queue       text NOT NULL,
  key         text NOT NULL,
  kind        text NOT NULL,
  state       smallint NOT NULL DEFAULT 0,
  owner       text NOT NULL DEFAULT '',
  lease_until timestamp without time zone,
  enqueued_at timestamp without time zone NOT NULL DEFAULT timezone('utc', now()),
  updated_at  timestamp without time zone NOT NULL DEFAULT timezone('utc', now()),
  UNIQUE (queue, key)
);
CREATE INDEX IF NOT EXISTS idx_work_item_claim ON public.work_item (queue, kind, state, id);
CREATE INDEX IF NOT EXISTS idx_work_item_owner ON public.work_item (queue, owner) WHERE state = 1;

-- +migrate Down

DROP INDEX IF EXISTS public.idx_work_item_owner;
DROP INDEX IF EXISTS public.idx_work_item_claim;
DROP TABLE IF EXISTS public.work_item;
