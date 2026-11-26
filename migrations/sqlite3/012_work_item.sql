-- +migrate Up

-- ============================================================================
-- OWASP Amass: work queues (SQLite)
--
-- work_item: the items of work the tools sharing the database divide among
-- themselves (repository.WorkQueue). Each item is named by its key, unique
-- in its queue, and has a kind that claims select by. state is 0 queued,
-- 1 leased to owner until lease_until (NULL: until acked or released), or
-- 2 done. id keeps the order items were first queued in. Times are UTC text,
-- as elsewhere in this schema.
-- ============================================================================

CREATE TABLE IF NOT EXISTS work_item (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  queue       TEXT NOT NULL,
  key         TEXT NOT NULL,
  kind        TEXT NOT NULL,
  state       INTEGER NOT NULL DEFAULT 0,
  owner       TEXT NOT NULL DEFAULT '',
  lease_until TEXT,
  enqueued_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  UNIQUE (queue, key)
);
CREATE INDEX IF NOT EXISTS idx_work_item_claim ON work_item (queue, kind, state, id);
CREATE INDEX IF NOT EXISTS idx_work_item_owner ON work_item (queue, owner) WHERE state = 1;

-- +migrate Down

DROP INDEX IF EXISTS idx_work_item_owner;
DROP INDEX IF EXISTS idx_work_item_claim;
DROP TABLE IF EXISTS work_item;
