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
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// Params: @record::jsonb
const upsertAutonomousSystemText = `SELECT public.autonomoussystem_upsert_entity_json(@record::jsonb);`

// Param: @row_id
const selectAutonomousSystemByID = `
SELECT a.id, a.created_at, a.updated_at, a.asn, a.attrs
FROM public.autonomoussystem_get_by_id(@row_id) AS a;`

func (r *PostgresRepository) upsertAutonomousSystem(ctx context.Context, a *oamnet.AutonomousSystem) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid autonomous system provided")
	}
	if a.Number == 0 {
		return 0, errors.New("autonomous system number cannot be zero")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.autonomous_system.upsert",
		SQLText: upsertAutonomousSystemText,
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

func (r *PostgresRepository) fetchAutonomousSystemByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.autonomous_system.by_id",
		SQLText: selectAutonomousSystemByID,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id, asn int64
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &asn, &attrsJSON); err != nil {
		return nil, err
	}

	e := &types.Entity{
		ID:    strconv.FormatInt(eid, 10),
		Asset: &oamnet.AutonomousSystem{Number: int(asn)},
	}

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
