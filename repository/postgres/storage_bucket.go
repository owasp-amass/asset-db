// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// Params: @record::jsonb
const upsertStorageBucketText = `SELECT public.storagebucket_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectStorageBucketByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.unique_id, a.bucket_name, a.provider, a.service,
a.bucket_exists, a.is_public
FROM public.storagebucket_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectStorageBucketFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.bucket_name, a.provider,
a.service, a.bucket_exists, a.is_public
FROM public.storagebucket_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectStorageBucketSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.bucket_name, a.provider,
a.service, a.bucket_exists, a.is_public
FROM public.storagebucket_updated_since(@since::timestamp, @limit::integer) AS a;`

func (r *PostgresRepository) upsertStorageBucket(ctx context.Context, a *oamplat.StorageBucket) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid storage bucket provided")
	}
	if a.ID == "" {
		return 0, fmt.Errorf("the storage bucket does not have a unique identifier")
	}
	if a.Name == "" {
		return 0, fmt.Errorf("the storage bucket %s does not have a name", a.ID)
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	var id int64
	j := NewRowJob(ctx, upsertStorageBucketText, pgx.NamedArgs{
		"record": string(record),
	}, func(row pgx.Row) error {
		return row.Scan(&id)
	})

	r.wpool.Submit(j)
	return id, j.Wait()
}

// storageBucketRow holds the columns read for one storage bucket.
type storageBucketRow struct {
	eid, rid          int64
	created, updated  time.Time
	provider, service pgtype.Text
	bucket            oamplat.StorageBucket
}

// dest returns the scan destinations after the entity ID, in column order.
func (s *storageBucketRow) dest() []any {
	return []any{&s.rid, &s.created, &s.updated, &s.bucket.ID, &s.bucket.Name,
		&s.provider, &s.service, &s.bucket.Exists, &s.bucket.Public}
}

func (r *PostgresRepository) fetchStorageBucketByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	s := storageBucketRow{eid: eid}

	j := NewRowJob(ctx, selectStorageBucketByIDText, pgx.NamedArgs{
		"row_id": rowID,
	}, func(row pgx.Row) error {
		return row.Scan(s.dest()...)
	})

	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	return buildStorageBucketEntity(&s)
}

func (r *PostgresRepository) findStorageBucketsByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
	if !since.IsZero() {
		since = since.UTC()
	}
	ts := zeronull.Timestamp(since)

	if len(filters) == 0 {
		return nil, errors.New("no filters provided")
	}

	filtersJSON, err := json.Marshal(filters)
	if err != nil {
		return nil, err
	}

	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	return r.scanStorageBuckets(ctx, selectStorageBucketFindByContentText, pgx.NamedArgs{
		"filters": string(filtersJSON),
		"since":   ts,
		"limit":   lmt,
	})
}

func (r *PostgresRepository) getStorageBucketsUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	return r.scanStorageBuckets(ctx, selectStorageBucketSinceText, pgx.NamedArgs{
		"since": since.UTC(),
		"limit": lmt,
	})
}

// scanStorageBuckets runs a query whose rows are an entity ID followed by the
// columns of the StorageBuckets updated-since query, and builds the entities.
func (r *PostgresRepository) scanStorageBuckets(ctx context.Context, query string, args pgx.NamedArgs) ([]*dbt.Entity, error) {
	var out []*dbt.Entity
	j := NewRowsJob(ctx, query, args, func(rows pgx.Rows) error {
		for rows.Next() {
			var s storageBucketRow

			if err := rows.Scan(append([]any{&s.eid}, s.dest()...)...); err != nil {
				continue
			}
			if ent, err := buildStorageBucketEntity(&s); err == nil {
				out = append(out, ent)
			}
		}
		return rows.Err()
	})

	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	return out, nil
}

func buildStorageBucketEntity(s *storageBucketRow) (*dbt.Entity, error) {
	if s.rid == 0 {
		return nil, fmt.Errorf("no storage bucket record found with row ID %d", s.rid)
	}
	if s.bucket.ID == "" {
		return nil, fmt.Errorf("storage bucket record with row ID %d is missing its unique ID", s.rid)
	}

	a := s.bucket
	a.Provider = s.provider.String
	a.Service = s.service.String

	return &dbt.Entity{
		ID:        strconv.FormatInt(s.eid, 10),
		CreatedAt: s.created.In(time.UTC).Local(),
		LastSeen:  s.updated.In(time.UTC).Local(),
		Asset:     &a,
	}, nil
}
