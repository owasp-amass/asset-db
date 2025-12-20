// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/owasp-amass/asset-db/types"
	oamfile "github.com/owasp-amass/open-asset-model/file"
)

// Params: @record::jsonb
const upsertFileText = `SELECT public.file_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectFileByID = `
SELECT a.id, a.created_at, a.updated_at, a.file_url, a.basename, a.file_type, a.attrs
FROM public.file_get_by_id(@row_id::bigint) AS a;`

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

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.file.upsert",
		SQLText: upsertFileText,
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

func (r *PostgresRepository) fetchFileByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.file.by_id",
		SQLText: selectFileByID,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var a oamfile.File
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &a.URL, &a.Name, &a.Type, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, errors.New("no file found")
	}
	if a.URL == "" {
		return nil, errors.New("file URL is missing")
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

	return e, nil
}
