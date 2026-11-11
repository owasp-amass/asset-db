// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// Replaces every organization column and its attributes, as the upsert
// stores them, without keeping a stored value for an empty field.
// Params: @unique_id, @org_name, @legal_name, @jurisdiction, @registration_id, @founding_date,
// @industry, @target_markets::jsonb, @active, @non_profit, @headcount
const replaceOrganizationText = `
UPDATE public.organization AS o SET
    org_name        = @org_name,
    legal_name      = NULLIF(@legal_name, ''),
    jurisdiction    = NULLIF(@jurisdiction, ''),
    registration_id = NULLIF(@registration_id, ''),
    attrs           = jsonb_strip_nulls(jsonb_build_object(
        'founding_date',  NULLIF(@founding_date, '')::timestamp,
        'industry',       NULLIF(@industry, ''),
        'target_markets', NULLIF(@target_markets::jsonb, '[]'::jsonb),
        'active',         @active::boolean,
        'non_profit',     @non_profit::boolean,
        'headcount',      NULLIF(@headcount::integer, 0)
    )),
    updated_at      = now()
WHERE o.unique_id = @unique_id
RETURNING (SELECT e.entity_id FROM public.entity AS e
           WHERE e.table_name = 'public.organization'::citext AND e.row_id = o.id);`

// ReplaceAsset implements the AssetReplacer interface: it stores the
// asset's content exactly, clearing the fields it leaves empty.
func (r *PostgresRepository) ReplaceAsset(ctx context.Context, asset oam.Asset) (*dbt.Entity, error) {
	o, ok := asset.(*oamorg.Organization)
	if !ok || o == nil {
		return nil, fmt.Errorf("replacing a %T is not supported", asset)
	}
	if o.ID == "" || o.Name == "" {
		return nil, errors.New("the organization ID and name are required")
	}

	markets := o.TargetMarkets
	if markets == nil {
		markets = []string{}
	}
	mj, err := json.Marshal(markets)
	if err != nil {
		return nil, err
	}

	var eid int64
	j := NewRowJob(ctx, replaceOrganizationText, pgx.NamedArgs{
		"unique_id":       o.ID,
		"org_name":        o.Name,
		"legal_name":      o.LegalName,
		"jurisdiction":    o.Jurisdiction,
		"registration_id": o.RegistrationID,
		"founding_date":   o.FoundingDate,
		"industry":        o.Industry,
		"target_markets":  string(mj),
		"active":          o.Active,
		"non_profit":      o.NonProfit,
		"headcount":       o.Headcount,
	}, func(row pgx.Row) error {
		return row.Scan(&eid)
	})

	r.wpool.Submit(j)
	if err := j.Wait(); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("no organization %q to replace", o.ID)
		}
		return nil, err
	}

	return r.FindEntityById(ctx, strconv.FormatInt(eid, 10))
}
