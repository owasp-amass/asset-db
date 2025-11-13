// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// Params: :unique_id, :legal_name, :org_name, :jurisdiction, :registration_id, :attrs
const upsertOrganizationText = `
INSERT INTO organization(unique_id, legal_name, org_name, jurisdiction, registration_id, attrs)
VALUES (:unique_id, :legal_name, :org_name, :jurisdiction, :registration_id, :attrs)
ON CONFLICT(unique_id) DO UPDATE SET
    legal_name      = COALESCE(excluded.legal_name,      organization.legal_name),
    org_name        = COALESCE(excluded.org_name,        organization.org_name),
    jurisdiction    = COALESCE(excluded.jurisdiction,    organization.jurisdiction),
    registration_id = COALESCE(excluded.registration_id, organization.registration_id),
    attrs           = COALESCE(excluded.attrs,           organization.attrs),
    updated_at      = CURRENT_TIMESTAMP`

// Param: :unique_id
const selectEntityIDByOrganizationText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'organization' LIMIT 1)
  AND natural_key = :unique_id
LIMIT 1`

// Param: :row_id
const selectOrganizationByIDText = `
SELECT id, created_at, updated_at, org_name, unique_id, legal_name, jurisdiction, registration_id, attrs
FROM organization 
WHERE id = :row_id
LIMIT 1`

type organizationAttributes struct {
	FoundingDate  string   `json:"founding_date"`
	Industry      string   `json:"industry"`
	TargetMarkets []string `json:"target_markets"`
	Active        bool     `json:"active"`
	NonProfit     bool     `json:"non_profit"`
	Headcount     int      `json:"headcount"`
}

func (r *SqliteRepository) upsertOrganization(ctx context.Context, a *oamorg.Organization) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid organization provided")
	}
	if a.ID == "" {
		return 0, fmt.Errorf("the organization ID cannot be empty")
	}
	if a.Name == "" {
		return 0, fmt.Errorf("the organization name cannot be empty")
	}

	attrs := organizationAttributes{
		FoundingDate:  a.FoundingDate,
		Industry:      a.Industry,
		TargetMarkets: a.TargetMarkets,
		Active:        a.Active,
		NonProfit:     a.NonProfit,
		Headcount:     a.Headcount,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.organization.upsert",
		SQLText: upsertOrganizationText,
		Args: []any{
			sql.Named("unique_id", a.ID),
			sql.Named("org_name", a.Name),
			sql.Named("legal_name", a.LegalName),
			sql.Named("jurisdiction", a.Jurisdiction),
			sql.Named("registration_id", a.RegistrationID),
			sql.Named("attrs", attrsJSON),
		},
		Result: done,
	})
	err = <-done
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.organization.entity_id_by_organization",
		SQLText: selectEntityIDByOrganizationText,
		Args:    []any{sql.Named("unique_id", a.ID)},
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

func (r *SqliteRepository) fetchOrganizationByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.organization.by_id",
		SQLText: selectOrganizationByIDText,
		Args:    []any{sql.Named("row_id", rowID)},
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
