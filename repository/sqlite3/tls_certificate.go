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
	"time"

	"github.com/owasp-amass/asset-db/types"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	_ "modernc.org/sqlite"
)

// Params: :serial_number, :subject_common_name, :attrs
const upsertTLSCertificateText = `
INSERT INTO tlscertificate(serial_number, subject_common_name, attrs) 
VALUES (:serial_number, :subject_common_name, :attrs)
ON CONFLICT(cert_key) DO UPDATE SET
    subject_common_name = COALESCE(NULLIF(excluded.subject_common_name, ''), tlscertificate.subject_common_name),
    attrs               = json_patch(tlscertificate.attrs,       excluded.attrs),
    updated_at          = CURRENT_TIMESTAMP`

// Params: :serial_number, :attrs. A certificate is identified by its serial
// number with its issuer's common name and key identifier and its own key
// identifier (RFC 5280 makes serial numbers unique per issuer only): the
// same expression as the table's cert_key column.
const selectEntityIDByTLSCertificateText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'tlscertificate' LIMIT 1)
  AND natural_key = :serial_number || '|' || lower(coalesce(json_extract(:attrs, '$.issuer_common_name'), ''))
    || '|' || lower(coalesce(json_extract(:attrs, '$.authority_key_id'), ''))
    || '|' || lower(coalesce(json_extract(:attrs, '$.subject_key_id'), ''))
LIMIT 1`

// Param: :row_id
const selectTLSCertificateByIDText = `
SELECT id, created_at, updated_at, serial_number, subject_common_name, attrs
FROM tlscertificate 
WHERE id = :row_id
LIMIT 1`

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
	PublicKeySHA256       string   `json:"public_key_sha256,omitempty"`
}

func (r *SqliteRepository) upsertTLSCertificate(ctx context.Context, a *oamcert.TLSCertificate) (int64, error) {
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
	if _, err := parseTimestamp(a.NotBefore); err != nil {
		return 0, fmt.Errorf("the TLS certificate must have a valid NotBefore date: %v", err)
	}
	if _, err := parseTimestamp(a.NotAfter); err != nil {
		return 0, fmt.Errorf("the TLS certificate must have a valid NotAfter date: %v", err)
	}

	attrs := tlsCertificateAttributes{
		Version:               a.Version,
		IssuerCommonName:      a.IssuerCommonName,
		NotBefore:             a.NotBefore,
		NotAfter:              a.NotAfter,
		KeyUsage:              a.KeyUsage,
		ExtKeyUsage:           a.ExtKeyUsage,
		SignatureAlgorithm:    a.SignatureAlgorithm,
		PublicKeyAlgorithm:    a.PublicKeyAlgorithm,
		IsCA:                  a.IsCA,
		CRLDistributionPoints: a.CRLDistributionPoints,
		SubjectKeyID:          a.SubjectKeyID,
		AuthorityKeyID:        a.AuthorityKeyID,
		PublicKeySHA256:       a.PublicKeySHA256,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.tls_certificate.upsert",
		SQLText: upsertTLSCertificateText,
		Args: []any{
			sql.Named("serial_number", a.SerialNumber),
			sql.Named("subject_common_name", a.SubjectCommonName),
			sql.Named("attrs", string(attrsJSON)),
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
		Name:    "asset.tls_certificate.entity_id_by_tls_certificate",
		SQLText: selectEntityIDByTLSCertificateText,
		Args:    []any{sql.Named("serial_number", a.SerialNumber), sql.Named("attrs", string(attrsJSON))},
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

func (r *SqliteRepository) fetchTLSCertificateByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.tls_certificate.by_id",
		SQLText: selectTLSCertificateByIDText,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var c, u, attrsJSON string
	var a oamcert.TLSCertificate
	if err := result.Row.Scan(&row_id, &c, &u, &a.SerialNumber, &a.SubjectCommonName, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, fmt.Errorf("no TLS certificate found with row ID %d", rowID)
	}
	if a.SerialNumber == "" {
		return nil, errors.New("TLS certificate serial number is missing")
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
	a.PublicKeySHA256 = attrs.PublicKeySHA256

	if a.Version == "" {
		return nil, fmt.Errorf("the TLS certificate version is missing")
	} else if v, err := strconv.Atoi(a.Version); err != nil || v > 3 {
		return nil, fmt.Errorf("the TLS certificate version is not a valid integer <= 3: %v", err)
	}
	if _, err := parseTimestamp(a.NotBefore); err != nil {
		return nil, fmt.Errorf("the TLS certificate does not have a valid NotBefore date: %v", err)
	}
	if _, err := parseTimestamp(a.NotAfter); err != nil {
		return nil, fmt.Errorf("the TLS certificate does not have a valid NotAfter date: %v", err)
	}

	return e, nil
}
