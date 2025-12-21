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
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
)

// Params: @record::jsonb
const upsertTLSCertificateText = `SELECT public.tls_certificate_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectTLSCertificateByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.serial_number, a.subject_common_name, a.attrs
FROM public.tls_certificate_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectTLSCertificateFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.serial_number, a.subject_common_name, a.attrs 
FROM public.tlscertificate_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectTLSCertificateSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.serial_number, a.subject_common_name, a.attrs 
FROM public.tlscertificate_updated_since(@since::timestamp, @limit::integer) AS a;`

type tlsCertificateAttributes struct {
	Version               string   `json:"version,omitempty"`
	IssuerCommonName      string   `json:"issuer_common_name,omitempty"`
	NotBefore             string   `json:"not_before,omitempty"`
	NotAfter              string   `json:"not_after,omitempty"`
	KeyUsage              []string `json:"key_usage,omitempty"`
	ExtKeyUsage           []string `json:"ext_key_usage,omitempty"`
	SignatureAlgorithm    string   `json:"signature_algorithm,omitempty"`
	PublicKeyAlgorithm    string   `json:"public_key_algorithm,omitempty"`
	IsCA                  bool     `json:"is_ca,omitempty"`
	CRLDistributionPoints []string `json:"crl_distribution_points,omitempty"`
	SubjectKeyID          string   `json:"subject_key_id,omitempty"`
	AuthorityKeyID        string   `json:"authority_key_id,omitempty"`
}

func (r *PostgresRepository) upsertTLSCertificate(ctx context.Context, a *oamcert.TLSCertificate) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid TLS certificate provided")
	}
	if a.Version == "" {
		return 0, fmt.Errorf("the TLS certificate version cannot be empty")
	} else if v, err := strconv.Atoi(a.Version); err != nil || v > 3 {
		return 0, fmt.Errorf("the TLS certificate version must be a valid integer <= 3: %v", err)
	}
	if a.SerialNumber == "" {
		return 0, fmt.Errorf("the TLS certificate serial number cannot be empty")
	}
	if a.SubjectCommonName == "" {
		return 0, fmt.Errorf("the TLS certificate subject common name cannot be empty")
	}
	if a.IssuerCommonName == "" {
		return 0, fmt.Errorf("the TLS certificate issuer common name cannot be empty")
	}
	if _, err := parseTimestamp(a.NotBefore); err != nil {
		return 0, fmt.Errorf("the TLS certificate must have a valid NotBefore date: %v", err)
	}
	if _, err := parseTimestamp(a.NotAfter); err != nil {
		return 0, fmt.Errorf("the TLS certificate must have a valid NotAfter date: %v", err)
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.tls_certificate.upsert",
		SQLText: upsertTLSCertificateText,
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

func (r *PostgresRepository) fetchTLSCertificateByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.tls_certificate.by_id",
		SQLText: selectTLSCertificateByIDText,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var rid int64
	var c, u time.Time
	var attrsJSON string
	var a oamcert.TLSCertificate
	if err := result.Row.Scan(&rid, &c, &u, &a.SerialNumber, &a.SubjectCommonName, &attrsJSON); err != nil {
		return nil, err
	}

	e, err := r.buildTLSCertificateEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findTLSCertificatesByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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

	ch := make(chan *rowsResult, 1)
	r.wpool.Submit(&rowsJob{
		Ctx:     ctx,
		Name:    "asset.tls_certificate.find_by_content",
		SQLText: selectTLSCertificateFindByContentText,
		Args: pgx.NamedArgs{
			"filters": string(filtersJSON),
			"since":   ts,
			"limit":   limit,
		},
		Result: ch,
	})

	result := <-ch
	if result.Rows != nil {
		defer func() { _ = result.Rows.Close() }()
	}
	if result.Err != nil {
		return nil, result.Err
	}

	var out []*dbt.Entity
	for result.Rows.Next() {
		var eid, rid int64
		var c, u time.Time
		var attrsJSON string
		var a oamcert.TLSCertificate

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.SerialNumber, &a.SubjectCommonName, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildTLSCertificateEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) getTLSCertificatesUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	ch := make(chan *rowsResult, 1)
	r.wpool.Submit(&rowsJob{
		Ctx:     ctx,
		Name:    "asset.tls_certificate.updated_since",
		SQLText: selectTLSCertificateSinceText,
		Args: pgx.NamedArgs{
			"since": since,
			"limit": lmt,
		},
		Result: ch,
	})

	result := <-ch
	if result.Rows != nil {
		defer func() { _ = result.Rows.Close() }()
	}
	if result.Err != nil {
		return nil, result.Err
	}

	var out []*dbt.Entity
	for result.Rows.Next() {
		var eid, rid int64
		var c, u time.Time
		var attrsJSON string
		var a oamcert.TLSCertificate

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.SerialNumber, &a.SubjectCommonName, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildTLSCertificateEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) buildTLSCertificateEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *oamcert.TLSCertificate) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, fmt.Errorf("no TLS certificate found with row ID %d", rid)
	}
	if a.SerialNumber == "" {
		return nil, errors.New("TLS certificate serial number is missing")
	}
	if a.SubjectCommonName == "" {
		return nil, errors.New("TLS certificate subject common name is missing")
	}

	var attrs tlsCertificateAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Version = attrs.Version
	a.IssuerCommonName = attrs.IssuerCommonName
	a.NotBefore = attrs.NotBefore
	a.NotAfter = attrs.NotAfter
	a.KeyUsage = attrs.KeyUsage
	a.ExtKeyUsage = attrs.ExtKeyUsage
	a.SignatureAlgorithm = attrs.SignatureAlgorithm
	a.PublicKeyAlgorithm = attrs.PublicKeyAlgorithm
	a.IsCA = attrs.IsCA
	a.CRLDistributionPoints = attrs.CRLDistributionPoints
	a.SubjectKeyID = attrs.SubjectKeyID
	a.AuthorityKeyID = attrs.AuthorityKeyID

	if a.Version == "" {
		return nil, fmt.Errorf("the TLS certificate version is missing")
	} else if v, err := strconv.Atoi(a.Version); err != nil || v > 3 {
		return nil, fmt.Errorf("the TLS certificate version is not a valid integer <= 3: %v", err)
	}
	if a.IssuerCommonName == "" {
		return nil, fmt.Errorf("the TLS certificate issuer common name is missing")
	}

	if _, err := parseTimestamp(a.NotBefore); err != nil {
		return nil, fmt.Errorf("the TLS certificate does not have a valid NotBefore date: %v", err)
	}
	if _, err := parseTimestamp(a.NotAfter); err != nil {
		return nil, fmt.Errorf("the TLS certificate does not have a valid NotAfter date: %v", err)
	}

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
