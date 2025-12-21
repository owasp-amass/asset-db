// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// Params: @record::jsonb
const upsertNetblockText = `SELECT public.netblock_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectNetblockByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.netblock_cidr, a.attrs
FROM public.netblock_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectNetblockFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.netblock_cidr, a.attrs 
FROM public.netblock_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectNetblockSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.netblock_cidr, a.attrs 
FROM public.netblock_updated_since(@since::timestamp, @limit::integer) AS a;`

type netblockAttributes struct {
	Type string `json:"type,omitempty"`
}

func (r *PostgresRepository) upsertNetblock(ctx context.Context, a *oamnet.Netblock) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid netblock provided")
	}
	if !a.CIDR.IsValid() {
		return 0, errors.New("netblock CIDR is invalid")
	}
	if a.CIDR.Addr().IsUnspecified() {
		return 0, errors.New("unspecified IP addresses are not allowed")
	}

	switch a.Type {
	case "":
		return 0, errors.New("CIDR IP version cannot be empty")
	case "IPv4":
		if !a.CIDR.Addr().Is4() {
			return 0, errors.New("mismatched CIDR IP version and type")
		}
	case "IPv6":
		if !a.CIDR.Addr().Is6() {
			return 0, errors.New("mismatched CIDR IP version and type")
		}
	default:
		return 0, errors.New("CIDR IP version must be either IPv4 or IPv6")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.netblock.upsert",
		SQLText: upsertNetblockText,
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

func (r *PostgresRepository) fetchNetblockByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.netblock.by_id",
		SQLText: selectNetblockByIDText,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var rid int64
	var c, u time.Time
	var a oamnet.Netblock
	var cidrstr, attrsJSON string
	if err := result.Row.Scan(&rid, &c, &u, &cidrstr, &attrsJSON); err != nil {
		return nil, err
	}

	cidr, err := netip.ParsePrefix(cidrstr)
	if err != nil {
		return nil, err
	}
	a.CIDR = cidr

	e, err := r.buildNetblockEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findNetblocksByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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

	ch := make(chan *rowsResult, 1)
	r.wpool.Submit(&rowsJob{
		Ctx:     ctx,
		Name:    "asset.netblock.find_by_content",
		SQLText: selectNetblockFindByContentText,
		Args: pgx.NamedArgs{
			"filters": string(filtersJSON),
			"since":   ts,
			"limit":   limit,
		},
		Result: ch,
	})

	result := <-ch
	if result.Rows != nil {
		defer func() { _ = result.Rows.Close() }()
	}
	if result.Err != nil {
		return nil, result.Err
	}

	var out []*dbt.Entity
	for result.Rows.Next() {
		var eid, rid int64
		var c, u time.Time
		var a oamnet.Netblock
		var cidrstr, attrsJSON string

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &cidrstr, &attrsJSON); err != nil {
			continue
		}

		cidr, err := netip.ParsePrefix(cidrstr)
		if err != nil {
			return nil, err
		}
		a.CIDR = cidr

		if ent, err := r.buildNetblockEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) getNetblocksUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	ch := make(chan *rowsResult, 1)
	r.wpool.Submit(&rowsJob{
		Ctx:     ctx,
		Name:    "asset.netblock.updated_since",
		SQLText: selectNetblockSinceText,
		Args: pgx.NamedArgs{
			"since": since,
			"limit": lmt,
		},
		Result: ch,
	})

	result := <-ch
	if result.Rows != nil {
		defer func() { _ = result.Rows.Close() }()
	}
	if result.Err != nil {
		return nil, result.Err
	}

	var out []*dbt.Entity
	for result.Rows.Next() {
		var eid, rid int64
		var c, u time.Time
		var a oamnet.Netblock
		var cidrstr, attrsJSON string

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &cidrstr, &attrsJSON); err != nil {
			continue
		}

		cidr, err := netip.ParsePrefix(cidrstr)
		if err != nil {
			return nil, err
		}
		a.CIDR = cidr

		if ent, err := r.buildNetblockEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) buildNetblockEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *oamnet.Netblock) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, errors.New("no netblock record found")
	}
	if !a.CIDR.IsValid() {
		return nil, errors.New("CIDR is invalid")
	}
	if a.CIDR.Addr().IsUnspecified() {
		return nil, errors.New("the CIDR is unspecified")
	}

	var attrs netblockAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Type = attrs.Type

	switch a.Type {
	case "":
		return nil, errors.New("CIDR IP version cannot be empty")
	case "IPv4":
		if !a.CIDR.Addr().Is4() {
			return nil, errors.New("mismatched CIDR IP version and type")
		}
	case "IPv6":
		if !a.CIDR.Addr().Is6() {
			return nil, errors.New("mismatched CIDR IP version and type")
		}
	default:
		return nil, errors.New("CIDR IP version must be either IPv4 or IPv6")
	}

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
