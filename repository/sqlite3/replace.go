// Copyright © by Jeff Foley 2017-2026. All rights reserved.
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

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// Params: :unique_id, :org_name, :legal_name, :jurisdiction, :registration_id, :attrs
const replaceOrganizationText = `
UPDATE organization SET
    org_name        = :org_name,
    legal_name      = :legal_name,
    jurisdiction    = :jurisdiction,
    registration_id = :registration_id,
    attrs           = :attrs,
    updated_at      = CURRENT_TIMESTAMP
WHERE unique_id = :unique_id`

// ReplaceAsset implements the AssetReplacer interface: it stores the
// asset's content exactly, clearing the fields it leaves empty.
func (r *SqliteRepository) ReplaceAsset(ctx context.Context, asset oam.Asset) (*types.Entity, error) {
	o, ok := asset.(*oamorg.Organization)
	if !ok || o == nil {
		return nil, fmt.Errorf("replacing a %T is not supported", asset)
	}
	if o.ID == "" || o.Name == "" {
		return nil, errors.New("the organization ID and name are required")
	}

	// The entity must exist: a replacement never creates one.
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.organization.entity_id_by_organization",
		SQLText: selectEntityIDByOrganizationText,
		Args:    []any{sql.Named("unique_id", o.ID)},
		Result:  ch,
	})
	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var eid int64
	if err := result.Row.Scan(&eid); err != nil {
		return nil, fmt.Errorf("no organization %q to replace: %w", o.ID, err)
	}

	attrs, err := json.Marshal(organizationAttributes{
		FoundingDate:  o.FoundingDate,
		Industry:      o.Industry,
		TargetMarkets: o.TargetMarkets,
		Active:        o.Active,
		NonProfit:     o.NonProfit,
		Headcount:     o.Headcount,
	})
	if err != nil {
		return nil, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.organization.replace",
		SQLText: replaceOrganizationText,
		Args: []any{
			sql.Named("unique_id", o.ID),
			sql.Named("org_name", o.Name),
			// The SQLite schema stores an absent value as an empty string.
			sql.Named("legal_name", o.LegalName),
			sql.Named("jurisdiction", o.Jurisdiction),
			sql.Named("registration_id", o.RegistrationID),
			sql.Named("attrs", string(attrs)),
		},
		Result: done,
	})
	if err := <-done; err != nil {
		return nil, err
	}

	return r.FindEntityById(ctx, strconv.FormatInt(eid, 10))
}
