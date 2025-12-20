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
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// Params: @record::jsonb
const upsertDomainRecordText = `SELECT public.domainrecord_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectDomainRecordByID = `
SELECT a.id, a.created_at, a.updated_at, a.domain, a.record_name, a.punycode, a.extension, a.whois_server, a.object_id, a.attrs
FROM public.domainrecord_get_by_id(@row_id::bigint) AS a;`

type domainRecordAttributes struct {
	Raw            string   `json:"raw,omitempty"`
	Status         []string `json:"status,omitempty"`
	CreatedDate    string   `json:"created_date,omitempty"`
	UpdatedDate    string   `json:"updated_date,omitempty"`
	ExpirationDate string   `json:"expiration_date,omitempty"`
	DNSSEC         bool     `json:"dnssec"`
}

func (r *PostgresRepository) upsertDomainRecord(ctx context.Context, a *oamreg.DomainRecord) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid domain record provided")
	}
	if a.Domain == "" {
		return 0, errors.New("domain record domain cannot be empty")
	}
	if a.Name == "" {
		return 0, errors.New("domain record name cannot be empty")
	}
	if a.Punycode == "" {
		return 0, errors.New("domain record punycode cannot be empty")
	}
	if a.Extension == "" {
		return 0, errors.New("domain record extension cannot be empty")
	}
	if _, err := parseTimestamp(a.CreatedDate); err != nil {
		return 0, fmt.Errorf("domain record must have a valid created date: %v", err)
	}
	if _, err := parseTimestamp(a.UpdatedDate); err != nil {
		return 0, fmt.Errorf("domain record must have a valid updated date: %v", err)
	}
	if _, err := parseTimestamp(a.ExpirationDate); err != nil {
		return 0, fmt.Errorf("domain record must have a valid expiration date: %v", err)
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.domainrecord.upsert",
		SQLText: upsertDomainRecordText,
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

func (r *PostgresRepository) fetchDomainRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.domainrecord.by_id",
		SQLText: selectDomainRecordByID,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var a oamreg.DomainRecord
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &a.Domain, &a.Name,
		&a.Punycode, &a.Extension, &a.WhoisServer, &a.ID, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, errors.New("no domain record found")
	}
	if a.Domain == "" {
		return nil, errors.New("domain record domain is missing")
	}
	if a.Name == "" {
		return nil, errors.New("domain record name is missing")
	}
	if a.Punycode == "" {
		return nil, errors.New("domain record punycode is missing")
	}
	if a.Extension == "" {
		return nil, errors.New("domain record extension is missing")
	}
	if a.WhoisServer == "" {
		return nil, errors.New("domain record whois server is missing")
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

	var attrs domainRecordAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Raw = attrs.Raw
	a.Status = attrs.Status
	a.CreatedDate = attrs.CreatedDate
	a.UpdatedDate = attrs.UpdatedDate
	a.ExpirationDate = attrs.ExpirationDate
	a.DNSSEC = attrs.DNSSEC

	if _, err := parseTimestamp(a.CreatedDate); err != nil {
		return nil, fmt.Errorf("domain record created date is missing or invalid: %v", err)
	}
	if _, err := parseTimestamp(a.UpdatedDate); err != nil {
		return nil, fmt.Errorf("domain record updated date is missing or invalid: %v", err)
	}
	if _, err := parseTimestamp(a.ExpirationDate); err != nil {
		return nil, fmt.Errorf("domain record expiration date is missing or invalid: %v", err)
	}

	return e, nil
}
