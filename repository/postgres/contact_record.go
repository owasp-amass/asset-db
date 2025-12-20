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
	"github.com/owasp-amass/open-asset-model/contact"
)

// Params: @record::jsonb
const upsertContactRecordText = `SELECT public.contactrecord_upsert_entity_json(@record::jsonb);`

// Param: @row_id
const selectContactRecordByID = `
SELECT a.id, a.created_at, a.updated_at, a.discovered_at, a.attrs
FROM public.contactrecord_get_by_id(@row_id) AS a;`

func (r *PostgresRepository) upsertContactRecord(ctx context.Context, a *contact.ContactRecord) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid contact record provided")
	}
	if a.DiscoveredAt == "" {
		return 0, errors.New("contact record discovered_at cannot be empty")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.contact.upsert",
		SQLText: upsertContactRecordText,
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

func (r *PostgresRepository) fetchContactRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.contact.by_id",
		SQLText: selectContactRecordByID,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var c, u, disat, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &disat, &attrsJSON); err != nil {
		return nil, err
	}

	if disat == "" {
		return nil, errors.New("contact record discovered_at is missing")
	}

	e := &types.Entity{
		ID:    strconv.FormatInt(eid, 10),
		Asset: &contact.ContactRecord{DiscoveredAt: disat},
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
