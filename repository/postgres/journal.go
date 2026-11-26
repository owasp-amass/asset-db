// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/owasp-amass/asset-db/types"
)

const journalColumns = `seq, topic, kind, key, data, actor, at, cause`

// AppendJournal implements repository.JournalStore.
func (r *PostgresRepository) AppendJournal(ctx context.Context, rec *types.JournalRecord) (*types.JournalRecord, error) {
	if err := rec.Validate(); err != nil {
		return nil, err
	}

	out := *rec
	var cause *int64
	if rec.Cause > 0 {
		cause = &rec.Cause
	}
	j := NewRowJob(ctx, `INSERT INTO public.journal (topic, kind, key, data, actor, cause)
        VALUES (@topic, @kind, @key, @data::jsonb, @actor, @cause) RETURNING seq, at`,
		pgx.NamedArgs{"topic": rec.Topic, "kind": rec.Kind, "key": rec.Key, "data": rec.JournalData(),
			"actor": rec.Actor, "cause": cause}, func(row pgx.Row) error {
			return row.Scan(&out.Seq, &out.At)
		})
	r.wpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	out.At = out.At.In(time.UTC).Local()
	out.Data = json.RawMessage(rec.JournalData())
	return &out, nil
}

// ReadJournal implements repository.JournalStore.
func (r *PostgresRepository) ReadJournal(ctx context.Context, topic string, after int64, limit int) ([]*types.JournalRecord, error) {
	args := pgx.NamedArgs{"topic": topic, "after": after, "limit": nil}
	if limit > 0 {
		args["limit"] = limit
	}
	return r.queryJournal(ctx, `SELECT `+journalColumns+` FROM public.journal
        WHERE topic = @topic AND seq > @after ORDER BY seq LIMIT @limit::integer`, args)
}

// LatestJournal implements repository.JournalStore.
func (r *PostgresRepository) LatestJournal(ctx context.Context, topic, key string) (*types.JournalRecord, error) {
	recs, err := r.queryJournal(ctx, `SELECT `+journalColumns+` FROM public.journal
        WHERE topic = @topic AND key = @key ORDER BY seq DESC LIMIT 1`, pgx.NamedArgs{"topic": topic, "key": key})
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, errors.New("no journal record has this topic and key")
	}
	return recs[0], nil
}

func (r *PostgresRepository) queryJournal(ctx context.Context, query string, args pgx.NamedArgs) ([]*types.JournalRecord, error) {
	var out []*types.JournalRecord
	j := NewRowsJob(ctx, query, args, func(rows pgx.Rows) error {
		for rows.Next() {
			var rec types.JournalRecord
			var data []byte
			var cause *int64
			if err := rows.Scan(&rec.Seq, &rec.Topic, &rec.Kind, &rec.Key, &data, &rec.Actor, &rec.At,
				&cause); err != nil {
				return err
			}

			rec.At = rec.At.In(time.UTC).Local()
			rec.Data = json.RawMessage(data)
			if cause != nil {
				rec.Cause = *cause
			}
			out = append(out, &rec)
		}
		return rows.Err()
	})
	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}
	return out, nil
}

const leaseColumns = `name, holder, acquired_at, expires_at, data`

// AcquireLease implements repository.LeaseStore. The database's clock
// decides expiry, so holders on hosts whose clocks differ agree.
func (r *PostgresRepository) AcquireLease(ctx context.Context, name, holder string, ttl time.Duration,
	data json.RawMessage) (*types.Lease, bool, error) {
	if err := types.ValidateLease(name, holder, ttl, data); err != nil {
		return nil, false, err
	}
	if len(data) == 0 {
		data = json.RawMessage("{}")
	}

	acquired := false
	j := NewExecJob(ctx, `INSERT INTO public.lease (name, holder, acquired_at, expires_at, data)
        VALUES (@name, @holder, timezone('utc', now()),
          timezone('utc', now()) + make_interval(secs => @ttl::double precision), @data::jsonb)
        ON CONFLICT (name) DO UPDATE SET holder = excluded.holder,
          acquired_at = CASE WHEN lease.holder = excluded.holder THEN lease.acquired_at ELSE excluded.acquired_at END,
          expires_at = excluded.expires_at, data = excluded.data
        WHERE lease.holder = excluded.holder OR lease.expires_at <= excluded.acquired_at`,
		pgx.NamedArgs{"name": name, "holder": holder, "ttl": ttl.Seconds(), "data": string(data)},
		func(tag pgconn.CommandTag) error {
			acquired = tag.RowsAffected() > 0
			return nil
		})
	r.wpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, false, err
	}

	l, err := r.findLease(ctx, name, false)
	if err != nil {
		return nil, false, err
	}
	return l, acquired && l.Holder == holder, nil
}

// ReleaseLease implements repository.LeaseStore.
func (r *PostgresRepository) ReleaseLease(ctx context.Context, name, holder string) error {
	j := NewExecJob(ctx, `DELETE FROM public.lease WHERE name = @name AND holder = @holder`,
		pgx.NamedArgs{"name": name, "holder": holder}, func(pgconn.CommandTag) error { return nil })
	r.wpool.Submit(j)
	return j.Wait()
}

// FindLease implements repository.LeaseStore.
func (r *PostgresRepository) FindLease(ctx context.Context, name string) (*types.Lease, error) {
	return r.findLease(ctx, name, true)
}

// findLease returns the lease, only while it has not expired when live is
// set.
func (r *PostgresRepository) findLease(ctx context.Context, name string, live bool) (*types.Lease, error) {
	var out *types.Lease
	j := NewRowsJob(ctx, `SELECT `+leaseColumns+` FROM public.lease WHERE name = @name
        AND (NOT @live::boolean OR expires_at > timezone('utc', now()))`, pgx.NamedArgs{"name": name, "live": live},
		func(rows pgx.Rows) error {
			for rows.Next() {
				var l types.Lease
				var data []byte
				if err := rows.Scan(&l.Name, &l.Holder, &l.AcquiredAt, &l.ExpiresAt, &data); err != nil {
					return err
				}
				l.AcquiredAt, l.ExpiresAt = l.AcquiredAt.In(time.UTC).Local(), l.ExpiresAt.In(time.UTC).Local()
				l.Data = json.RawMessage(data)
				out = &l
			}
			return rows.Err()
		})
	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, errors.New("no live lease has this name")
	}
	return out, nil
}
