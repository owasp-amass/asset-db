// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// Params: :unique_id, :legal_name, :org_name, :active, :jurisdiction, :founding_date, :registration_id
const upsertOrganizationText = `
INSERT INTO organization(unique_id, legal_name, org_name, active, jurisdiction, founding_date, registration_id)
VALUES (:unique_id, :legal_name, :org_name, :active, :jurisdiction, :founding_date, :registration_id)
ON CONFLICT(unique_id) DO UPDATE SET
    legal_name      = COALESCE(excluded.legal_name,      organization.legal_name),
    org_name        = COALESCE(excluded.org_name,        organization.org_name),
    active          = COALESCE(excluded.active,          organization.active),
    jurisdiction    = COALESCE(excluded.jurisdiction,    organization.jurisdiction),
    founding_date   = COALESCE(excluded.founding_date,   organization.founding_date),
    registration_id = COALESCE(excluded.registration_id, organization.registration_id),
    updated_at      = CURRENT_TIMESTAMP;`

// Param: :unique_id
const selectEntityIDByOrganizationText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'organization' LIMIT 1)
  AND display_value = :unique_id
LIMIT 1;`

// Param: :row_id
const selectOrganizationByIDText = `
SELECT id, created_at, updated_at, org_name, active, unique_id, legal_name, jurisdiction, founding_date, registration_id 
FROM organization 
WHERE id = :row_id
LIMIT 1;`

type organization struct {
	ID             int64      `json:"id"`
	CreatedAt      *time.Time `json:"created_at,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
	OrgName        *string    `json:"org_name,omitempty"`
	Active         bool       `json:"active,omitempty"`
	UniqueID       string     `json:"unique_id"`
	LegalName      string     `json:"legal_name"`
	Jurisdiction   *string    `json:"jurisdiction,omitempty"`
	FoundingDate   *string    `json:"founding_date,omitempty"`
	RegistrationID *string    `json:"registration_id,omitempty"`
}

func (r *SqliteRepository) upsertOrganization(ctx context.Context, a *oamorg.Organization) (int64, error) {
	const keySel = "asset.organization.upsert"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, upsertOrganizationText)
	if err != nil {
		return 0, err
	}

	_ = stmt.QueryRowContext(ctx,
		sql.Named("unique_id", a.ID),
		sql.Named("org_name", a.Name),
		sql.Named("legal_name", a.LegalName),
		sql.Named("founding_date", a.FoundingDate),
		sql.Named("jurisdiction", a.Jurisdiction),
		sql.Named("registration_id", a.RegistrationID),
		sql.Named("active", a.Active),
	)

	const keySel2 = "asset.organization.entity_id_by_organization"
	stmt2, err := r.queries.getOrPrepare(ctx, keySel2, selectEntityIDByOrganizationText)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := stmt2.QueryRowContext(ctx, sql.Named("unique_id", a.ID)).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *SqliteRepository) fetchOrganizationByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	const keySel = "asset.organization.by_id"
	st, err := r.queries.getOrPrepare(ctx, keySel, selectOrganizationByIDText)
	if err != nil {
		return nil, err
	}

	var act *int64
	var a organization
	var c, u, fd *string
	if err := st.QueryRowContext(ctx, rowID).Scan(
		&a.ID, &c, &u, &a.OrgName, &act, &a.UniqueID, &a.LegalName, &a.Jurisdiction, &fd, &a.RegistrationID,
	); err != nil {
		return nil, err
	}

	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	if a.CreatedAt == nil || a.UpdatedAt == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	var orgname string
	if a.OrgName != nil {
		orgname = *a.OrgName
	}

	var jurisdiction string
	if a.Jurisdiction != nil {
		jurisdiction = *a.Jurisdiction
	}

	var fdate string
	if fd != nil {
		fdate = *fd
	}

	var regid string
	if a.RegistrationID != nil {
		regid = *a.RegistrationID
	}

	if act != nil {
		b := *act != 0
		a.Active = b
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: a.CreatedAt.In(time.UTC).Local(),
		LastSeen:  a.UpdatedAt.In(time.UTC).Local(),
		Asset: &oamorg.Organization{
			ID:             a.UniqueID,
			Name:           orgname,
			LegalName:      a.LegalName,
			FoundingDate:   fdate,
			Jurisdiction:   jurisdiction,
			RegistrationID: regid,
			Active:         a.Active,
		},
	}, nil
}
