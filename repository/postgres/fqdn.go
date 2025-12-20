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
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// Params: @record::jsonb
const upsertFQDNText = `SELECT public.fqdn_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectFQDNByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.fqdn, a.attrs
FROM public.fqdn_get_by_id(@row_id::bigint) AS a;`

func (r *PostgresRepository) upsertFQDN(ctx context.Context, a *oamdns.FQDN) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid FQDN provided")
	}
	if a.Name == "" {
		return 0, errors.New("FQDN name cannot be empty")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.fqdn.upsert",
		SQLText: upsertFQDNText,
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

func (r *PostgresRepository) fetchFQDNByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.fqdn.by_id",
		SQLText: selectFQDNByIDText,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var a oamdns.FQDN
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &a.Name, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, errors.New("no FQDN record found")
	}
	if a.Name == "" {
		return nil, errors.New("FQDN name is missing")
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
