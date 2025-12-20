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
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

// Params: @record::jsonb
const upsertURLText = `SELECT public.url_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectURLByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.raw_url, a.scheme, a.attrs
FROM public.url_get_by_id(@row_id::bigint) AS a;`

type urlAttributes struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Path     string `json:"path,omitempty"`
	Options  string `json:"options,omitempty"`
	Fragment string `json:"fragment,omitempty"`
}

func (r *PostgresRepository) upsertURL(ctx context.Context, a *oamurl.URL) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid URL provided")
	}
	if a.Raw == "" {
		return 0, fmt.Errorf("the URL raw string cannot be empty")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.url.upsert",
		SQLText: upsertURLText,
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

func (r *PostgresRepository) fetchURLByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.url.by_id",
		SQLText: selectURLByIDText,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var a oamurl.URL
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &a.Raw, &a.Scheme, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, fmt.Errorf("no URL found with row ID %d", rowID)
	}
	if a.Raw == "" {
		return nil, fmt.Errorf("URL at row ID %d has a missing raw string", rowID)
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

	var attrs urlAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Username = attrs.Username
	a.Password = attrs.Password
	a.Host = attrs.Host
	a.Port = attrs.Port
	a.Path = attrs.Path
	a.Options = attrs.Options
	a.Fragment = attrs.Fragment

	return e, nil
}
