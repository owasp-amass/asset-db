// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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
	"github.com/owasp-amass/asset-db/types"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// Params: @record::jsonb
const upsertProductReleaseText = `SELECT public.product_release_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectProductReleaseByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.release_name, a.attrs 
FROM public.product_release_get_by_id(@row_id::bigint) AS a;`

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

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.product_release.upsert",
		SQLText: upsertProductReleaseText,
		Args:    pgx.NamedArgs{"record": string(record)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return 0, result.Err
	}

	var id int64
	if err := result.Row.Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *PostgresRepository) fetchProductReleaseByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.product_release.by_id",
		SQLText: selectProductReleaseByIDText,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var c, u, attrsJSON string
	var a oamplat.ProductRelease
	if err := result.Row.Scan(&row_id, &c, &u, &a.Name, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, fmt.Errorf("no product release found with row ID %d", rowID)
	}
	if a.Name == "" {
		return nil, fmt.Errorf("product release at row ID %d has no name", rowID)
	}

	e := &types.Entity{ID: strconv.FormatInt(eid, 10), Asset: &a}
	if created, err := parseTimestamp(c); err != nil {
		return nil, err
	} else {
		e.CreatedAt = created.In(time.UTC).Local()
	}
	if updated, err := parseTimestamp(u); err != nil {
		return nil, err
	} else {
		e.LastSeen = updated.In(time.UTC).Local()
	}

	var attrs productReleaseAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.ReleaseDate = attrs.ReleaseDate

	return e, nil
}
