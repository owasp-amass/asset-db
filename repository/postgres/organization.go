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
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// Params: @record::jsonb
const upsertOrganizationText = `SELECT public.organization_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectOrganizationByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.org_name, a.unique_id, a.legal_name, a.jurisdiction, a.registration_id, a.attrs
FROM public.organization_get_by_id(@row_id::bigint) AS a;`

type organizationAttributes struct {
	FoundingDate  string   `json:"founding_date,omitempty"`
	Industry      string   `json:"industry,omitempty"`
	TargetMarkets []string `json:"target_markets,omitempty"`
	Active        bool     `json:"active"`
	NonProfit     bool     `json:"non_profit,omitempty"`
	Headcount     int      `json:"headcount,omitempty"`
}

func (r *PostgresRepository) upsertOrganization(ctx context.Context, a *oamorg.Organization) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid organization provided")
	}
	if a.ID == "" {
		return 0, fmt.Errorf("the organization ID cannot be empty")
	}
	if a.Name == "" {
		return 0, fmt.Errorf("the organization name cannot be empty")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.organization.upsert",
		SQLText: upsertOrganizationText,
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

func (r *PostgresRepository) fetchOrganizationByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.organization.by_id",
		SQLText: selectOrganizationByIDText,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var a oamorg.Organization
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &a.Name, &a.ID,
		&a.LegalName, &a.Jurisdiction, &a.RegistrationID, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, errors.New("no organization found")
	}
	if a.Name == "" {
		return nil, errors.New("organization name is missing")
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

	var attrs organizationAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.FoundingDate = attrs.FoundingDate
	a.Industry = attrs.Industry
	a.TargetMarkets = attrs.TargetMarkets
	a.Active = attrs.Active
	a.NonProfit = attrs.NonProfit
	a.Headcount = attrs.Headcount

	return e, nil
}
