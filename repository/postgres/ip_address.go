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
const upsertIPAddressText = `SELECT public.ipaddress_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectIPAddressByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.ip_address, a.attrs
FROM public.ipaddress_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectIPAddressFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.ip_address, a.attrs 
FROM public.ipaddress_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectIPAddressSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.ip_address, a.attrs 
FROM public.ipaddress_updated_since(@since::timestamp, @limit::integer) AS a;`

type ipAddressAttributes struct {
	Type string `json:"type,omitempty"`
}

func (r *PostgresRepository) upsertIPAddress(ctx context.Context, a *oamnet.IPAddress) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid IP address provided")
	}
	if !a.Address.IsValid() {
		return 0, errors.New("IP address is invalid")
	}
	if a.Address.IsUnspecified() {
		return 0, errors.New("unspecified IP addresses are not allowed")
	}

	switch a.Type {
	case "":
		return 0, errors.New("IP address type cannot be empty")
	case "IPv4":
		if !a.Address.Is4() {
			return 0, errors.New("mismatched IP address and type")
		}
	case "IPv6":
		if !a.Address.Is6() {
			return 0, errors.New("mismatched IP address and type")
		}
	default:
		return 0, errors.New("IP address type must be either IPv4 or IPv6")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	var id int64
	j := NewRowJob(ctx, upsertIPAddressText, pgx.NamedArgs{
		"record": string(record),
	}, func(row pgx.Row) error {
		return row.Scan(&id)
	})

	r.pool.Submit(j)
	return id, j.Wait()
}

func (r *PostgresRepository) fetchIPAddressByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	var rid int64
	var c, u time.Time
	var a oamnet.IPAddress
	var addrstr, attrsJSON string

	j := NewRowJob(ctx, selectIPAddressByIDText, pgx.NamedArgs{
		"row_id": rowID,
	}, func(row pgx.Row) error {
		return row.Scan(&rid, &c, &u, &addrstr, &attrsJSON)
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	addr, err := netip.ParseAddr(addrstr)
	if err != nil {
		return nil, err
	}
	a.Address = addr

	e, err := r.buildIPAddressEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}

	return e, nil
}

func (r *PostgresRepository) findIPAddressesByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
	j := NewRowsJob(ctx, selectIPAddressFindByContentText, pgx.NamedArgs{
		"filters": string(filtersJSON),
		"since":   ts,
		"limit":   lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var a oamnet.IPAddress
			var addrstr, attrsJSON string

			if err := rows.Scan(&eid, &rid, &c, &u, &addrstr, &a.Type, &attrsJSON); err != nil {
				continue
			}

			addr, err := netip.ParseAddr(addrstr)
			if err != nil {
				continue
			}
			a.Address = addr

			if ent, err := r.buildIPAddressEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
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

func (r *PostgresRepository) getIPAddressesUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	var out []*dbt.Entity
	j := NewRowsJob(ctx, selectIPAddressSinceText, pgx.NamedArgs{
		"since": since.UTC(),
		"limit": lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var a oamnet.IPAddress
			var addrstr, attrsJSON string

			if err := rows.Scan(&eid, &rid, &c, &u, &addrstr, &a.Type, &attrsJSON); err != nil {
				continue
			}

			addr, err := netip.ParseAddr(addrstr)
			if err != nil {
				continue
			}
			a.Address = addr

			if ent, err := r.buildIPAddressEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
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

func (r *PostgresRepository) buildIPAddressEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *oamnet.IPAddress) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, errors.New("no IP address found")
	}
	if !a.Address.IsValid() || a.Address.IsUnspecified() {
		return nil, errors.New("IP address is invalid or unspecified")
	}

	var attrs ipAddressAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Type = attrs.Type

	switch a.Type {
	case "":
		return nil, errors.New("IP address type is missing")
	case "IPv4":
		if !a.Address.Is4() {
			return nil, errors.New("mismatched IP address and type")
		}
	case "IPv6":
		if !a.Address.Is6() {
			return nil, errors.New("mismatched IP address and type")
		}
	default:
		return nil, errors.New("IP address type must be either IPv4 or IPv6")
	}

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
