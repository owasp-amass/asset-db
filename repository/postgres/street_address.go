// Copyright © by Jeff Foley 2017-2026. All rights reserved.
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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
)

// Params: @record::jsonb
const upsertStreetAddressText = `SELECT public.streetaddress_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectStreetAddressByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.street_address, a.city, a.country, a.unit,
	   a.building, a.province, a.locality, a.postal_code, a.street_name, a.building_number, a.attrs
FROM public.streetaddress_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectStreetAddressFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.street_address, a.city, a.country, a.unit, a.building, a.province, a.locality, a.postal_code, a.street_name, a.building_number, a.attrs
FROM public.streetaddress_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectStreetAddressSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.street_address, a.city, a.country, a.unit, a.building, a.province, a.locality, a.postal_code, a.street_name, a.building_number, a.attrs
FROM public.streetaddress_updated_since(@since::timestamp, @limit::integer) AS a;`

type streetAddressAttributes struct {
	POBox string `json:"po_box,omitempty"`
	GLN   int    `json:"gln,omitempty"`
}

func (r *PostgresRepository) upsertStreetAddress(ctx context.Context, a *contact.StreetAddress) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid street address provided")
	}
	if a.Address == "" {
		return 0, errors.New("the street address cannot be empty")
	}
	if a.City == "" {
		return 0, errors.New("street address city cannot be empty")
	}
	if a.Country == "" {
		return 0, errors.New("street address country cannot be empty")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	var id int64
	j := NewRowJob(ctx, upsertStreetAddressText, pgx.NamedArgs{
		"record": string(record),
	}, func(row pgx.Row) error {
		return row.Scan(&id)
	})

	r.wpool.Submit(j)
	return id, j.Wait()
}

func (r *PostgresRepository) fetchStreetAddressByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	var rid int64
	var c, u time.Time
	var attrsJSON string
	var a contact.StreetAddress
	var unit, building, province, locality pgtype.Text
	var postalCode, streetName, buildingNumber pgtype.Text

	j := NewRowJob(ctx, selectStreetAddressByIDText, pgx.NamedArgs{
		"row_id": rowID,
	}, func(row pgx.Row) error {
		return row.Scan(&rid, &c, &u, &a.Address, &a.City, &a.Country, &unit, &building,
			&province, &locality, &postalCode, &streetName, &buildingNumber, &attrsJSON)
	})

	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	if unit.Valid {
		a.Unit = unit.String
	}
	if building.Valid {
		a.Building = building.String
	}
	if province.Valid {
		a.Province = province.String
	}
	if locality.Valid {
		a.Locality = locality.String
	}
	if postalCode.Valid {
		a.PostalCode = postalCode.String
	}
	if streetName.Valid {
		a.StreetName = streetName.String
	}
	if buildingNumber.Valid {
		a.BuildingNumber = buildingNumber.String
	}

	e, err := r.buildStreetAddressEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findStreetAddressesByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
	j := NewRowsJob(ctx, selectStreetAddressFindByContentText, pgx.NamedArgs{
		"filters": string(filtersJSON),
		"since":   ts,
		"limit":   lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a contact.StreetAddress
			var unit, building, province, locality pgtype.Text
			var postalCode, streetName, buildingNumber pgtype.Text

			if err := rows.Scan(&eid, &rid, &c, &u, &a.Address, &a.City,
				&a.Country, &unit, &building, &province, &locality,
				&postalCode, &streetName, &buildingNumber, &attrsJSON); err != nil {
				continue
			}
			if unit.Valid {
				a.Unit = unit.String
			}
			if building.Valid {
				a.Building = building.String
			}
			if province.Valid {
				a.Province = province.String
			}
			if locality.Valid {
				a.Locality = locality.String
			}
			if postalCode.Valid {
				a.PostalCode = postalCode.String
			}
			if streetName.Valid {
				a.StreetName = streetName.String
			}
			if buildingNumber.Valid {
				a.BuildingNumber = buildingNumber.String
			}

			if ent, err := r.buildStreetAddressEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
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

func (r *PostgresRepository) getStreetAddressesUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	return r.scanStreetAddresses(ctx, selectStreetAddressSinceText, pgx.NamedArgs{
		"since": since.UTC(),
		"limit": lmt,
	})
}

// scanStreetAddresses runs a query whose rows are an entity ID followed by the
// columns of the StreetAddresses updated-since query, and builds the entities.
func (r *PostgresRepository) scanStreetAddresses(ctx context.Context, query string, args pgx.NamedArgs) ([]*dbt.Entity, error) {
	var out []*dbt.Entity
	j := NewRowsJob(ctx, query, args, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a contact.StreetAddress
			var unit, building, province, locality pgtype.Text
			var postalCode, streetName, buildingNumber pgtype.Text

			if err := rows.Scan(&eid, &rid, &c, &u, &a.Address, &a.City,
				&a.Country, &unit, &building, &province, &locality,
				&postalCode, &streetName, &buildingNumber, &attrsJSON); err != nil {
				continue
			}
			if unit.Valid {
				a.Unit = unit.String
			}
			if building.Valid {
				a.Building = building.String
			}
			if province.Valid {
				a.Province = province.String
			}
			if locality.Valid {
				a.Locality = locality.String
			}
			if postalCode.Valid {
				a.PostalCode = postalCode.String
			}
			if streetName.Valid {
				a.StreetName = streetName.String
			}
			if buildingNumber.Valid {
				a.BuildingNumber = buildingNumber.String
			}

			if ent, err := r.buildStreetAddressEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
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

func (r *PostgresRepository) buildStreetAddressEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *contact.StreetAddress) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, errors.New("no street address found")
	}
	if a.Address == "" {
		return nil, errors.New("the street address is missing")
	}
	if a.City == "" {
		return nil, errors.New("street address city is missing")
	}
	if a.Country == "" {
		return nil, errors.New("street address country is missing")
	}

	var attrs streetAddressAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.POBox = attrs.POBox
	a.GLN = attrs.GLN

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
