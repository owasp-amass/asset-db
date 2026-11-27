// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/owasp-amass/asset-db/types"
)

const journalColumns = `seq, topic, kind, key, data, actor, at, cause`

// AppendJournal implements repository.JournalStore.
func (r *SqliteRepository) AppendJournal(ctx context.Context, rec *types.JournalRecord) (*types.JournalRecord, error) {
	if err := rec.Validate(); err != nil {
		return nil, err
	}

	out := *rec
	var at string
	cause := sql.NullInt64{Int64: rec.Cause, Valid: rec.Cause > 0}
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{Ctx: ctx, Name: "journal.append", SQLText: `INSERT INTO journal (topic, kind, key, data,
        actor, cause) VALUES (:topic, :kind, :key, :data, :actor, :cause) RETURNING seq, at`,
		Args: []any{sql.Named("topic", rec.Topic), sql.Named("kind", rec.Kind), sql.Named("key", rec.Key),
			sql.Named("data", rec.JournalData()), sql.Named("actor", rec.Actor), sql.Named("cause", cause)},
		Returning: []any{&out.Seq, &at}, Result: done})
	if err := <-done; err != nil {
		return nil, err
	}

	t, err := parseTimestamp(at)
	if err != nil {
		return nil, err
	}
	out.At = t.In(time.UTC).Local()
	out.Data = json.RawMessage(rec.JournalData())
	return &out, nil
}

// ReadJournal implements repository.JournalStore.
func (r *SqliteRepository) ReadJournal(ctx context.Context, topic string, after int64, limit int) ([]*types.JournalRecord, error) {
	return r.ReadJournalFiltered(ctx, topic, types.JournalFilter{}, after, limit)
}

// ReadJournalFiltered implements repository.JournalStore. Only the filter's
// conditions are added to the query, so each read uses the index that fits
// it: (topic, key, seq) or (topic, kind, seq).
func (r *SqliteRepository) ReadJournalFiltered(ctx context.Context, topic string, f types.JournalFilter,
	after int64, limit int) ([]*types.JournalRecord, error) {
	q := `SELECT ` + journalColumns + ` FROM journal WHERE topic = :topic AND seq > :after`
	args := []any{sql.Named("topic", topic), sql.Named("after", after)}
	if f.Key != "" {
		q += ` AND key = :key`
		args = append(args, sql.Named("key", f.Key))
	}
	if len(f.Kinds) > 0 {
		marks := make([]string, len(f.Kinds))
		for i, k := range f.Kinds {
			name := fmt.Sprintf("kind%d", i)
			marks[i] = ":" + name
			args = append(args, sql.Named(name, k))
		}
		q += ` AND kind IN (` + strings.Join(marks, ", ") + `)`
	}
	q += ` ORDER BY seq`
	if limit > 0 {
		q += ` LIMIT :limit`
		args = append(args, sql.Named("limit", limit))
	}
	// the reader keeps a prepared statement by name: each shape of the query
	// is named by its text
	return r.queryJournal(ctx, q, q, args...)
}

// LatestJournal implements repository.JournalStore.
func (r *SqliteRepository) LatestJournal(ctx context.Context, topic, key string) (*types.JournalRecord, error) {
	recs, err := r.queryJournal(ctx, "journal.latest", `SELECT `+journalColumns+` FROM journal
        WHERE topic = :topic AND key = :key ORDER BY seq DESC LIMIT 1`, sql.Named("topic", topic),
		sql.Named("key", key))
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, errors.New("no journal record has this topic and key")
	}
	return recs[0], nil
}

func (r *SqliteRepository) queryJournal(ctx context.Context, name, query string, args ...any) ([]*types.JournalRecord, error) {
	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{Ctx: ctx, Name: name, SQLText: query, Args: args, Result: ch})
	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}
	defer func() { _ = result.Rows.Close() }()

	var out []*types.JournalRecord
	for result.Rows.Next() {
		var rec types.JournalRecord
		var data, at string
		var cause sql.NullInt64
		if err := result.Rows.Scan(&rec.Seq, &rec.Topic, &rec.Kind, &rec.Key, &data, &rec.Actor, &at,
			&cause); err != nil {
			return nil, err
		}

		t, err := parseTimestamp(at)
		if err != nil {
			return nil, err
		}
		rec.At = t.In(time.UTC).Local()
		rec.Data = json.RawMessage(data)
		rec.Cause = cause.Int64
		out = append(out, &rec)
	}
	return out, result.Rows.Err()
}

const leaseColumns = `name, holder, acquired_at, expires_at, data`

// AcquireLease implements repository.LeaseStore.
func (r *SqliteRepository) AcquireLease(ctx context.Context, name, holder string, ttl time.Duration,
	data json.RawMessage) (*types.Lease, bool, error) {
	if err := types.ValidateLease(name, holder, ttl, data); err != nil {
		return nil, false, err
	}
	if len(data) == 0 {
		data = json.RawMessage("{}")
	}

	now := time.Now().UTC()
	var got string
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{Ctx: ctx, Name: "lease.acquire", SQLText: `INSERT INTO lease (name, holder, acquired_at,
        expires_at, data) VALUES (:name, :holder, :now, :expires, :data)
        ON CONFLICT (name) DO UPDATE SET holder = excluded.holder,
          acquired_at = CASE WHEN lease.holder = excluded.holder THEN lease.acquired_at ELSE excluded.acquired_at END,
          expires_at = excluded.expires_at, data = excluded.data
        WHERE lease.holder = excluded.holder OR lease.expires_at <= excluded.acquired_at
        RETURNING holder`,
		Args: []any{sql.Named("name", name), sql.Named("holder", holder),
			sql.Named("now", now.Format(runTimeLayout)), sql.Named("expires", now.Add(ttl).Format(runTimeLayout)),
			sql.Named("data", string(data))},
		Returning: []any{&got}, Result: done})
	err := <-done
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}

	l, ferr := r.findLease(ctx, name)
	if ferr != nil {
		return nil, false, ferr
	}
	return l, err == nil && l.Holder == holder, nil
}

// ReleaseLease implements repository.LeaseStore.
func (r *SqliteRepository) ReleaseLease(ctx context.Context, name, holder string) error {
	return r.write(ctx, "lease.release", `DELETE FROM lease WHERE name = :name AND holder = :holder`,
		sql.Named("name", name), sql.Named("holder", holder))
}

// FindLease implements repository.LeaseStore.
func (r *SqliteRepository) FindLease(ctx context.Context, name string) (*types.Lease, error) {
	l, err := r.findLease(ctx, name)
	if err != nil {
		return nil, err
	}
	if !l.ExpiresAt.After(time.Now()) {
		return nil, errors.New("the lease has expired")
	}
	return l, nil
}

// findLease returns the lease row, expired or not.
func (r *SqliteRepository) findLease(ctx context.Context, name string) (*types.Lease, error) {
	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{Ctx: ctx, Name: "lease.find", SQLText: `SELECT ` + leaseColumns + ` FROM lease
        WHERE name = :name`, Args: []any{sql.Named("name", name)}, Result: ch})
	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}
	defer func() { _ = result.Rows.Close() }()

	if !result.Rows.Next() {
		if err := result.Rows.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("no lease has this name")
	}

	var l types.Lease
	var acquired, expires, data string
	if err := result.Rows.Scan(&l.Name, &l.Holder, &acquired, &expires, &data); err != nil {
		return nil, err
	}
	a, err := parseTimestamp(acquired)
	if err != nil {
		return nil, err
	}
	e, err := parseTimestamp(expires)
	if err != nil {
		return nil, err
	}
	l.AcquiredAt, l.ExpiresAt = a.In(time.UTC).Local(), e.In(time.UTC).Local()
	l.Data = json.RawMessage(data)
	return &l, nil
}
