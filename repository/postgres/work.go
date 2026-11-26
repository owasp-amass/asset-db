// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/owasp-amass/asset-db/types"
)

// workLeaseUntil is a lease's end ttl seconds from the database's now, or
// no end when ttl is 0.
const workLeaseUntil = `CASE WHEN @ttl::double precision > 0
          THEN timezone('utc', now()) + make_interval(secs => @ttl::double precision) END`

// EnqueueWork implements repository.WorkQueue.
func (r *PostgresRepository) EnqueueWork(ctx context.Context, queue, kind string, keys ...string) error {
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

	j := NewExecJob(ctx, `INSERT INTO public.work_item (queue, key, kind)
        SELECT @queue, k, @kind FROM unnest(@keys::text[]) AS k
        ON CONFLICT (queue, key) DO UPDATE SET kind = excluded.kind, state = 0, owner = '',
          lease_until = NULL, updated_at = timezone('utc', now())`,
		pgx.NamedArgs{"queue": queue, "kind": kind, "keys": keys}, func(pgconn.CommandTag) error { return nil })
	r.wpool.Submit(j)
	return j.Wait()
}

// HasWork implements repository.WorkQueue.
func (r *PostgresRepository) HasWork(ctx context.Context, queue string, keys ...string) (map[string]bool, error) {
	keys, err := types.WorkKeys(queue, keys)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(keys))
	if len(keys) == 0 {
		return out, nil
	}

	j := NewRowsJob(ctx, `SELECT key FROM public.work_item WHERE queue = @queue AND key = ANY(@keys::text[])`,
		pgx.NamedArgs{"queue": queue, "keys": keys}, func(rows pgx.Rows) error {
			for rows.Next() {
				var k string
				if err := rows.Scan(&k); err != nil {
					return err
				}
				out[k] = true
			}
			return rows.Err()
		})
	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}
	return out, nil
}

// ClaimWork implements repository.WorkQueue. Engines claiming at once each
// skip the items another is claiming.
func (r *PostgresRepository) ClaimWork(ctx context.Context, queue, kind, owner string, n int,
	ttl time.Duration) ([]string, error) {
	if err := types.ValidateWorkClaim(queue, kind, owner, n, ttl); err != nil {
		return nil, err
	}

	type claimed struct {
		id  int64
		key string
	}
	var got []claimed
	j := NewRowsJob(ctx, `UPDATE public.work_item w SET state = 1, owner = @owner,
          lease_until = `+workLeaseUntil+`, updated_at = timezone('utc', now())
        FROM (SELECT id FROM public.work_item WHERE queue = @queue AND kind = @kind
            AND (state = 0 OR (state = 1 AND lease_until <= timezone('utc', now())))
          ORDER BY id LIMIT @n FOR UPDATE SKIP LOCKED) c
        WHERE w.id = c.id
        RETURNING w.id, w.key`,
		pgx.NamedArgs{"queue": queue, "kind": kind, "owner": owner, "n": n, "ttl": ttl.Seconds()},
		func(rows pgx.Rows) error {
			for rows.Next() {
				var c claimed
				if err := rows.Scan(&c.id, &c.key); err != nil {
					return err
				}
				got = append(got, c)
			}
			return rows.Err()
		})
	r.wpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	sort.Slice(got, func(i, k int) bool { return got[i].id < got[k].id })
	keys := make([]string, 0, len(got))
	for _, c := range got {
		keys = append(keys, c.key)
	}
	return keys, nil
}

// RenewWork implements repository.WorkQueue.
func (r *PostgresRepository) RenewWork(ctx context.Context, queue, owner string, ttl time.Duration) (int64, error) {
	if queue == "" || owner == "" || ttl < 0 {
		return 0, errors.New("a renewal names its queue and owner, and a lease time of at least 0")
	}

	var n int64
	j := NewExecJob(ctx, `UPDATE public.work_item SET lease_until = `+workLeaseUntil+`,
          updated_at = timezone('utc', now())
        WHERE queue = @queue AND owner = @owner AND state = 1`,
		pgx.NamedArgs{"queue": queue, "owner": owner, "ttl": ttl.Seconds()},
		func(tag pgconn.CommandTag) error {
			n = tag.RowsAffected()
			return nil
		})
	r.wpool.Submit(j)
	if err := j.Wait(); err != nil {
		return 0, err
	}
	return n, nil
}

// AckWork implements repository.WorkQueue.
func (r *PostgresRepository) AckWork(ctx context.Context, queue, key, owner string) error {
	if queue == "" || key == "" {
		return errors.New("an ack names its queue and item")
	}

	var n int64
	j := NewExecJob(ctx, `UPDATE public.work_item SET state = 2, owner = '', lease_until = NULL,
          updated_at = timezone('utc', now())
        WHERE queue = @queue AND key = @key AND (@owner::text = '' OR (state = 1 AND owner = @owner::text))`,
		pgx.NamedArgs{"queue": queue, "key": key, "owner": owner}, func(tag pgconn.CommandTag) error {
			n = tag.RowsAffected()
			return nil
		})
	r.wpool.Submit(j)
	if err := j.Wait(); err != nil {
		return err
	}
	if owner != "" && n == 0 {
		return types.ErrWorkNotLeased
	}
	return nil
}

// ReleaseWork implements repository.WorkQueue.
func (r *PostgresRepository) ReleaseWork(ctx context.Context, queue, key, owner string) error {
	if queue == "" || key == "" {
		return errors.New("a release names its queue and item")
	}

	j := NewExecJob(ctx, `UPDATE public.work_item SET state = 0, owner = '', lease_until = NULL,
          updated_at = timezone('utc', now())
        WHERE queue = @queue AND key = @key AND state = 1 AND (@owner::text = '' OR owner = @owner::text)`,
		pgx.NamedArgs{"queue": queue, "key": key, "owner": owner}, func(pgconn.CommandTag) error { return nil })
	r.wpool.Submit(j)
	return j.Wait()
}

// CountWork implements repository.WorkQueue.
func (r *PostgresRepository) CountWork(ctx context.Context, queue, kind string) (types.WorkCounts, error) {
	var c types.WorkCounts
	j := NewRowJob(ctx, `SELECT
          COALESCE(SUM(CASE WHEN state = 0 OR (state = 1 AND lease_until <= timezone('utc', now()))
            THEN 1 ELSE 0 END), 0),
          COALESCE(SUM(CASE WHEN state = 1 AND (lease_until IS NULL OR lease_until > timezone('utc', now()))
            THEN 1 ELSE 0 END), 0),
          COALESCE(SUM(CASE WHEN state = 2 THEN 1 ELSE 0 END), 0)
        FROM public.work_item WHERE queue = @queue AND (@kind::text = '' OR kind = @kind::text)`,
		pgx.NamedArgs{"queue": queue, "kind": kind},
		func(row pgx.Row) error { return row.Scan(&c.Queued, &c.Leased, &c.Done) })
	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return types.WorkCounts{}, err
	}
	return c, nil
}

// DeleteQueue implements repository.WorkQueue.
func (r *PostgresRepository) DeleteQueue(ctx context.Context, queue string) error {
	if queue == "" {
		return errors.New("name the queue to delete")
	}

	j := NewExecJob(ctx, `DELETE FROM public.work_item WHERE queue = @queue`, pgx.NamedArgs{"queue": queue},
		func(pgconn.CommandTag) error { return nil })
	r.wpool.Submit(j)
	return j.Wait()
}
