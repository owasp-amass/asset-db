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

// ORGANIZATION ----------------------------------------------------------------
// Params: :unique_id, :legal_name, :org_name, :active, :jurisdiction, :founding_date, :registration_id, :attrs
const tmplUpsertOrganization = `
WITH
  row_try AS (
    INSERT INTO organization(unique_id, legal_name, org_name, active, jurisdiction, founding_date, registration_id)
    VALUES (:unique_id, :legal_name, :org_name, :active, :jurisdiction, :founding_date, :registration_id)
    ON CONFLICT(unique_id) DO UPDATE SET
      legal_name      = COALESCE(excluded.legal_name,      organization.legal_name),
      org_name        = COALESCE(excluded.org_name,        organization.org_name),
      active          = COALESCE(excluded.active,          organization.active),
      jurisdiction    = COALESCE(excluded.jurisdiction,    organization.jurisdiction),
      founding_date   = COALESCE(excluded.founding_date,   organization.founding_date),
      registration_id = COALESCE(excluded.registration_id, organization.registration_id),
      updated_at      = CASE WHEN
        (excluded.legal_name      IS NOT organization.legal_name) OR
        (excluded.org_name        IS NOT organization.org_name) OR
        (excluded.active          IS NOT organization.active) OR
        (excluded.jurisdiction    IS NOT organization.jurisdiction) OR
        (excluded.founding_date   IS NOT organization.founding_date) OR
        (excluded.registration_id IS NOT organization.registration_id)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE organization.updated_at END
    WHERE (excluded.legal_name      IS NOT organization.legal_name) OR
          (excluded.org_name        IS NOT organization.org_name) OR
          (excluded.active          IS NOT organization.active) OR
          (excluded.jurisdiction    IS NOT organization.jurisdiction) OR
          (excluded.founding_date   IS NOT organization.founding_date) OR
          (excluded.registration_id IS NOT organization.registration_id)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM organization WHERE unique_id=:unique_id LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('organization') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='organization' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), COALESCE(:legal_name,:unique_id), coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=COALESCE(:legal_name,:unique_id) LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'organization',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

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

func (s *Statements) UpsertOrganization(ctx context.Context, a *oamorg.Organization) (int64, error) {
	row := s.UpsertOrganizationStmt.QueryRowContext(ctx,
		sql.Named("unique_id", a.ID),
		sql.Named("org_name", a.Name),
		sql.Named("legal_name", a.LegalName),
		sql.Named("founding_date", a.FoundingDate),
		sql.Named("jurisdiction", a.Jurisdiction),
		sql.Named("registration_id", a.RegistrationID),
		sql.Named("active", a.Active),
		sql.Named("attrs", "{}"),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchOrganizationByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	query := `SELECT id, created_at, updated_at, org_name, active, unique_id, legal_name, jurisdiction, founding_date, registration_id
		      FROM organization WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "organization", query)
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
		CreatedAt: (*a.CreatedAt).In(time.UTC).Local(),
		LastSeen:  (*a.UpdatedAt).In(time.UTC).Local(),
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
