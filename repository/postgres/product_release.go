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
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// Params: @record::jsonb
const upsertProductReleaseText = `SELECT public.productrelease_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectProductReleaseByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.release_name, a.attrs 
FROM public.productrelease_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectProductReleaseFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.release_name, a.attrs 
FROM public.productrelease_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectProductReleaseSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.release_name, a.attrs 
FROM public.productrelease_updated_since(@since::timestamp, @limit::integer) AS a;`

type productReleaseAttributes struct {
	ReleaseDate string `json:"release_date,omitempty"`
}

func (r *PostgresRepository) upsertProductRelease(ctx context.Context, a *oamplat.ProductRelease) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid product release provided")
	}
	if a.Name == "" {
		return 0, fmt.Errorf("the product release name cannot be empty")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	var id int64
	j := NewRowJob(ctx, upsertProductReleaseText, pgx.NamedArgs{
		"record": string(record),
	}, func(row pgx.Row) error {
		return row.Scan(&id)
	})

	r.wpool.Submit(j)
	return id, j.Wait()
}

func (r *PostgresRepository) fetchProductReleaseByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	var row_id int64
	var c, u time.Time
	var attrsJSON string
	var a oamplat.ProductRelease

	j := NewRowJob(ctx, selectProductReleaseByIDText, pgx.NamedArgs{
		"row_id": rowID,
	}, func(row pgx.Row) error {
		return row.Scan(&row_id, &c, &u, &a.Name, &attrsJSON)
	})

	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	e, err := r.buildProductReleaseEntity(eid, row_id, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findProductReleasesByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
	j := NewRowsJob(ctx, selectProductReleaseFindByContentText, pgx.NamedArgs{
		"filters": string(filtersJSON),
		"since":   ts,
		"limit":   lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a oamplat.ProductRelease

			if err := rows.Scan(&eid, &rid, &c, &u, &a.Name, &attrsJSON); err != nil {
				continue
			}

			if ent, err := r.buildProductReleaseEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
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

func (r *PostgresRepository) getProductReleasesUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	var out []*dbt.Entity
	j := NewRowsJob(ctx, selectProductReleaseSinceText, pgx.NamedArgs{
		"since": since.UTC(),
		"limit": lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a oamplat.ProductRelease

			if err := rows.Scan(&eid, &rid, &c, &u, &a.Name, &attrsJSON); err != nil {
				continue
			}

			if ent, err := r.buildProductReleaseEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
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

func (r *PostgresRepository) buildProductReleaseEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *oamplat.ProductRelease) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, fmt.Errorf("no product release found with row ID %d", rid)
	}
	if a.Name == "" {
		return nil, fmt.Errorf("product release at row ID %d has no name", rid)
	}

	var attrs productReleaseAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.ReleaseDate = attrs.ReleaseDate

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
