// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	oamfile "github.com/owasp-amass/open-asset-model/file"
)

// Params: @record::jsonb
const upsertFileText = `SELECT public.file_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectFileByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.file_url, a.basename, a.file_type, a.attrs
FROM public.file_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectFileFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.file_url, a.basename, a.file_type, a.attrs 
FROM public.file_get_by_filters(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectFileSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.file_url, a.basename, a.file_type, a.attrs 
FROM public.file_updated_since(@since::timestamp, @limit::integer) AS a;`

func (r *PostgresRepository) upsertFile(ctx context.Context, a *oamfile.File) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid file provided")
	}
	if a.URL == "" {
		return 0, errors.New("file URL cannot be empty")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	var id int64
	j := NewRowJob(ctx, upsertFileText, pgx.NamedArgs{
		"record": string(record),
	}, func(row pgx.Row) error {
		return row.Scan(&id)
	})

	r.pool.Submit(j)
	return id, j.Wait()
}

func (r *PostgresRepository) fetchFileByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	var rid int64
	var a oamfile.File
	var c, u time.Time
	var attrsJSON string

	j := NewRowJob(ctx, selectFileByIDText, pgx.NamedArgs{
		"row_id": rowID,
	}, func(row pgx.Row) error {
		return row.Scan(&rid, &c, &u, &a.URL, &a.Name, &a.Type, &attrsJSON)
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	e, err := r.buildFileEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findFilesByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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

	var out []*dbt.Entity
	j := NewRowsJob(ctx, selectFileFindByContentText, pgx.NamedArgs{
		"filters": string(filtersJSON),
		"since":   ts,
		"limit":   lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a oamfile.File

			if err := rows.Scan(&eid, &rid, &c, &u, &a.URL, &a.Name, &a.Type, &attrsJSON); err != nil {
				continue
			}

			if ent, err := r.buildFileEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
				out = append(out, ent)
			}
		}
		return rows.Err()
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	return out, nil
}

func (r *PostgresRepository) getFilesUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	var out []*dbt.Entity
	j := NewRowsJob(ctx, selectFileSinceText, pgx.NamedArgs{
		"since": since.UTC(),
		"limit": lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a oamfile.File

			if err := rows.Scan(&eid, &rid, &c, &u, &a.URL, &a.Name, &a.Type, &attrsJSON); err != nil {
				continue
			}

			if ent, err := r.buildFileEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
				out = append(out, ent)
			}
		}
		return rows.Err()
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	return out, nil
}

func (r *PostgresRepository) buildFileEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *oamfile.File) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, errors.New("no file found")
	}
	if a.URL == "" {
		return nil, errors.New("file URL is missing")
	}

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
