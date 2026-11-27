// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/owasp-amass/asset-db/types"
)

// workTimes are now and the end of a lease ttl from now (NULL when ttl is
// 0), as stored.
func workTimes(ttl time.Duration) (string, any) {
	now := time.Now().UTC()
	if ttl <= 0 {
		return now.Format(runTimeLayout), nil
	}
	return now.Format(runTimeLayout), now.Add(ttl).Format(runTimeLayout)
}

// EnqueueWork implements repository.WorkQueue.
func (r *SqliteRepository) EnqueueWork(ctx context.Context, queue, kind string, keys ...string) error {
	keys, err := types.WorkKeys(queue, keys)
	if err != nil {
		return err
	}
	if kind == "" {
		return errors.New("work has a kind")
	}
	if len(keys) == 0 {
		return nil
	}
	list, err := json.Marshal(keys)
	if err != nil {
		return err
	}

	now, _ := workTimes(0)
	return r.write(ctx, "work.enqueue", `INSERT INTO work_item (queue, key, kind, enqueued_at, updated_at)
        SELECT :queue, value, :kind, :now, :now FROM json_each(:keys) WHERE true
        ON CONFLICT (queue, key) DO UPDATE SET kind = excluded.kind, state = 0, owner = '',
          lease_until = NULL, updated_at = excluded.updated_at
        WHERE work_item.state = 2`,
		sql.Named("queue", queue), sql.Named("kind", kind), sql.Named("now", now), sql.Named("keys", string(list)))
}

// HasWork implements repository.WorkQueue.
func (r *SqliteRepository) HasWork(ctx context.Context, queue string, keys ...string) (map[string]bool, error) {
	keys, err := types.WorkKeys(queue, keys)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(keys))
	if len(keys) == 0 {
		return out, nil
	}
	list, err := json.Marshal(keys)
	if err != nil {
		return nil, err
	}

	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{Ctx: ctx, Name: "work.has", SQLText: `SELECT key FROM work_item
        WHERE queue = :queue AND key IN (SELECT value FROM json_each(:keys))`,
		Args: []any{sql.Named("queue", queue), sql.Named("keys", string(list))}, Result: ch})
	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}
	defer func() { _ = result.Rows.Close() }()

	for result.Rows.Next() {
		var k string
		if err := result.Rows.Scan(&k); err != nil {
			return nil, err
		}
		out[k] = true
	}
	return out, result.Rows.Err()
}

// ClaimWork implements repository.WorkQueue. The writer serializes claims,
// so no item is claimed twice.
func (r *SqliteRepository) ClaimWork(ctx context.Context, queue, kind, owner string, n int,
	ttl time.Duration) ([]string, error) {
	if err := types.ValidateWorkClaim(queue, kind, owner, n, ttl); err != nil {
		return nil, err
	}

	type claimed struct {
		id  int64
		key string
	}
	var got []claimed
	now, until := workTimes(ttl)
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{Ctx: ctx, Name: "work.claim", SQLText: `UPDATE work_item SET state = 1, owner = :owner,
          lease_until = :until, updated_at = :now
        WHERE id IN (SELECT id FROM work_item WHERE queue = :queue AND kind = :kind
            AND (state = 0 OR (state = 1 AND lease_until <= :now))
          ORDER BY id LIMIT :n)
        RETURNING id, key`,
		Args: []any{sql.Named("queue", queue), sql.Named("kind", kind), sql.Named("owner", owner),
			sql.Named("until", until), sql.Named("now", now), sql.Named("n", n)},
		Rows: func(rows *sql.Rows) error {
			// a retried write runs this again
			got = got[:0]
			for rows.Next() {
				var c claimed
				if err := rows.Scan(&c.id, &c.key); err != nil {
					return err
				}
				got = append(got, c)
			}
			return nil
		}, Result: done})
	if err := <-done; err != nil {
		return nil, err
	}

	// RETURNING gives no order
	sort.Slice(got, func(i, k int) bool { return got[i].id < got[k].id })
	keys := make([]string, 0, len(got))
	for _, c := range got {
		keys = append(keys, c.key)
	}
	return keys, nil
}

// RenewWork implements repository.WorkQueue.
func (r *SqliteRepository) RenewWork(ctx context.Context, queue, owner string, ttl time.Duration) (int64, error) {
	if queue == "" || owner == "" || ttl < 0 {
		return 0, errors.New("a renewal names its queue and owner, and a lease time of at least 0")
	}

	var n int64
	now, until := workTimes(ttl)
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{Ctx: ctx, Name: "work.renew", SQLText: `UPDATE work_item SET lease_until = :until,
          updated_at = :now
        WHERE queue = :queue AND owner = :owner AND state = 1
        RETURNING id`,
		Args: []any{sql.Named("queue", queue), sql.Named("owner", owner), sql.Named("until", until),
			sql.Named("now", now)},
		Rows: func(rows *sql.Rows) error {
			// a retried write runs this again
			n = 0
			for rows.Next() {
				n++
			}
			return nil
		}, Result: done})
	if err := <-done; err != nil {
		return 0, err
	}
	return n, nil
}

// AckWork implements repository.WorkQueue.
func (r *SqliteRepository) AckWork(ctx context.Context, queue, key, owner string) error {
	if queue == "" || key == "" {
		return errors.New("an ack names its queue and item")
	}

	var id int64
	now, _ := workTimes(0)
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{Ctx: ctx, Name: "work.ack", SQLText: `UPDATE work_item SET state = 2,
          lease_until = NULL, updated_at = :now
        WHERE queue = :queue AND key = :key AND (:owner = '' OR (state = 1 AND owner = :owner))
        RETURNING id`,
		Args: []any{sql.Named("queue", queue), sql.Named("key", key), sql.Named("owner", owner),
			sql.Named("now", now)},
		Returning: []any{&id}, Result: done})
	err := <-done
	if errors.Is(err, sql.ErrNoRows) {
		if owner != "" {
			return types.ErrWorkNotLeased
		}
		return nil
	}
	return err
}

// ReleaseWork implements repository.WorkQueue.
func (r *SqliteRepository) ReleaseWork(ctx context.Context, queue, key, owner string) error {
	if queue == "" || key == "" {
		return errors.New("a release names its queue and item")
	}

	now, _ := workTimes(0)
	return r.write(ctx, "work.release", `UPDATE work_item SET state = 0, owner = '', lease_until = NULL,
          updated_at = :now
        WHERE queue = :queue AND key = :key AND state = 1 AND (:owner = '' OR owner = :owner)`,
		sql.Named("queue", queue), sql.Named("key", key), sql.Named("owner", owner), sql.Named("now", now))
}

// CountWorkByKind implements repository.WorkQueue.
func (r *SqliteRepository) CountWorkByKind(ctx context.Context, queue string) (types.WorkByKind, error) {
	now, _ := workTimes(0)
	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{Ctx: ctx, Name: "work.count_by_kind", SQLText: `SELECT kind,
          COALESCE(SUM(CASE WHEN state = 0 OR (state = 1 AND lease_until <= :now) THEN 1 ELSE 0 END), 0),
          COALESCE(SUM(CASE WHEN state = 1 AND (lease_until IS NULL OR lease_until > :now) THEN 1 ELSE 0 END), 0),
          COALESCE(SUM(CASE WHEN state = 2 THEN 1 ELSE 0 END), 0)
        FROM work_item WHERE queue = :queue GROUP BY kind`,
		Args: []any{sql.Named("queue", queue), sql.Named("now", now)}, Result: ch})
	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}
	defer func() { _ = result.Rows.Close() }()

	out := types.WorkByKind{}
	for result.Rows.Next() {
		var kind string
		var c types.WorkCounts
		if err := result.Rows.Scan(&kind, &c.Queued, &c.Leased, &c.Done); err != nil {
			return nil, err
		}
		out[kind] = c
	}
	return out, result.Rows.Err()
}

// CountWorkByOwner implements repository.WorkQueue.
func (r *SqliteRepository) CountWorkByOwner(ctx context.Context, queue string) (map[string]types.WorkCounts, error) {
	now, _ := workTimes(0)
	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{Ctx: ctx, Name: "work.count_by_owner", SQLText: `SELECT owner,
          COALESCE(SUM(CASE WHEN state = 1 AND lease_until <= :now THEN 1 ELSE 0 END), 0),
          COALESCE(SUM(CASE WHEN state = 1 AND (lease_until IS NULL OR lease_until > :now) THEN 1 ELSE 0 END), 0),
          COALESCE(SUM(CASE WHEN state = 2 THEN 1 ELSE 0 END), 0)
        FROM work_item WHERE queue = :queue AND owner <> '' GROUP BY owner`,
		Args: []any{sql.Named("queue", queue), sql.Named("now", now)}, Result: ch})
	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}
	defer func() { _ = result.Rows.Close() }()

	out := map[string]types.WorkCounts{}
	for result.Rows.Next() {
		var owner string
		var c types.WorkCounts
		if err := result.Rows.Scan(&owner, &c.Queued, &c.Leased, &c.Done); err != nil {
			return nil, err
		}
		out[owner] = c
	}
	return out, result.Rows.Err()
}

// DeleteQueue implements repository.WorkQueue.
func (r *SqliteRepository) DeleteQueue(ctx context.Context, queue string) error {
	if queue == "" {
		return errors.New("name the queue to delete")
	}
	return r.write(ctx, "work.delete", `DELETE FROM work_item WHERE queue = :queue`, sql.Named("queue", queue))
}
