// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// Params: :domain_text, :record_name, :punycode, :extension, :whois_server, :object_id, :attrs
const upsertDomainRecordText = `
INSERT INTO domainrecord(domain, record_name, punycode, extension, whois_server, object_id, attrs)
VALUES (:domain_text, :record_name, :punycode, :extension, :whois_server, :object_id, :attrs)
ON CONFLICT(domain) DO UPDATE SET
	record_name  = COALESCE(excluded.record_name,  domainrecord.record_name),
    punycode     = COALESCE(excluded.punycode,     domainrecord.punycode),
    extension    = COALESCE(excluded.extension,    domainrecord.extension),
    whois_server = COALESCE(excluded.whois_server, domainrecord.whois_server),
	object_id    = COALESCE(excluded.object_id,    domainrecord.object_id),
	attrs        = json_patch(domainrecord.attrs,  excluded.attrs),
    updated_at   = CURRENT_TIMESTAMP`

// Param: :domain_text
const selectEntityIDByDomainRecordText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'domainrecord' LIMIT 1)
  AND natural_key = lower(:domain_text)
LIMIT 1`

// Param: :row_id
const selectDomainRecordByID = `
SELECT id, created_at, updated_at, domain, record_name, punycode, extension, whois_server, object_id, attrs
FROM domainrecord
WHERE id = :row_id
LIMIT 1`

type domainRecordAttributes struct {
	Raw            string   `json:"raw,omitempty"`
	Status         []string `json:"status,omitempty"`
	CreatedDate    string   `json:"created_date,omitempty"`
	UpdatedDate    string   `json:"updated_date,omitempty"`
	ExpirationDate string   `json:"expiration_date,omitempty"`
	DNSSEC         bool     `json:"dnssec"`
}

func (r *SqliteRepository) upsertDomainRecord(ctx context.Context, a *oamreg.DomainRecord) (int64, error) {
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

	attrs := domainRecordAttributes{
		Raw:            a.Raw,
		Status:         a.Status,
		CreatedDate:    a.CreatedDate,
		UpdatedDate:    a.UpdatedDate,
		ExpirationDate: a.ExpirationDate,
		DNSSEC:         a.DNSSEC,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.domainrecord.upsert",
		SQLText: upsertDomainRecordText,
		Args: []any{
			sql.Named("domain_text", a.Domain),
			sql.Named("record_name", a.Name),
			sql.Named("punycode", a.Punycode),
			sql.Named("extension", a.Extension),
			sql.Named("whois_server", a.WhoisServer),
			sql.Named("object_id", a.ID),
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
		Name:    "asset.domainrecord.entity_id_by_domain",
		SQLText: selectEntityIDByDomainRecordText,
		Args:    []any{sql.Named("domain_text", a.Domain)},
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

func (r *SqliteRepository) fetchDomainRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.domainrecord.by_id",
		SQLText: selectDomainRecordByID,
		Args:    []any{sql.Named("row_id", rowID)},
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

	return e, nil
}
