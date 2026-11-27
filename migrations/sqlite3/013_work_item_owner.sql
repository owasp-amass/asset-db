-- +migrate Up

-- ============================================================================
-- OWASP Amass: work items by owner (SQLite)
--
-- An item keeps the owner that did it once done, so the queue's work can be
-- counted by owner in any state (repository.WorkQueue CountWorkByOwner). The
-- owner index covers every state, replacing the one on leased items only.
-- ============================================================================

DROP INDEX IF EXISTS idx_work_item_owner;
CREATE INDEX IF NOT EXISTS idx_work_item_queue_owner ON work_item (queue, owner);

-- +migrate Down

DROP INDEX IF EXISTS idx_work_item_queue_owner;
CREATE INDEX IF NOT EXISTS idx_work_item_owner ON work_item (queue, owner) WHERE state = 1;
