// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
)

// Params: :serial_number, :subject_common_name, :is_ca, :tls_version, :key_usage,
//
//	:ext_key_usage, :not_before, :not_after, :subject_key_id, :authority_key_id,
//	:issuer_common_name, :signature_algorithm, :public_key_algorithm, :crl_distribution_points
const upsertTLSCertificateText = `
INSERT INTO tlscertificate(
    serial_number, subject_common_name, is_ca, tls_version, key_usage, ext_key_usage,
    not_before, not_after, subject_key_id, authority_key_id, issuer_common_name,
    signature_algorithm, public_key_algorithm, crl_distribution_points) 
VALUES (
    :serial_number, :subject_common_name, :is_ca, :tls_version, :key_usage, :ext_key_usage,
    :not_before, :not_after, :subject_key_id, :authority_key_id, :issuer_common_name,
    :signature_algorithm, :public_key_algorithm, :crl_distribution_points)
ON CONFLICT(serial_number) DO UPDATE SET
    subject_common_name   = COALESCE(excluded.subject_common_name,   tlscertificate.subject_common_name),
    is_ca                 = COALESCE(excluded.is_ca,                 tlscertificate.is_ca),
    tls_version           = COALESCE(excluded.tls_version,           tlscertificate.tls_version),
    key_usage             = COALESCE(excluded.key_usage,             tlscertificate.key_usage),
    ext_key_usage         = COALESCE(excluded.ext_key_usage,         tlscertificate.ext_key_usage),
    not_before            = COALESCE(excluded.not_before,            tlscertificate.not_before),
    not_after             = COALESCE(excluded.not_after,             tlscertificate.not_after),
    subject_key_id        = COALESCE(excluded.subject_key_id,        tlscertificate.subject_key_id),
    authority_key_id      = COALESCE(excluded.authority_key_id,      tlscertificate.authority_key_id),
    issuer_common_name    = COALESCE(excluded.issuer_common_name,    tlscertificate.issuer_common_name),
    signature_algorithm   = COALESCE(excluded.signature_algorithm,   tlscertificate.signature_algorithm),
    public_key_algorithm  = COALESCE(excluded.public_key_algorithm,  tlscertificate.public_key_algorithm),
    crl_distribution_points=COALESCE(excluded.crl_distribution_points,tlscertificate.crl_distribution_points),
    updated_at            = CURRENT_TIMESTAMP`

// Param: :serial_number
const selectEntityIDByTLSCertificateText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'tlscertificate' LIMIT 1)
  AND natural_key = :serial_number
LIMIT 1`

// Param: :row_id
const selectTLSCertificateByIDText = `
SELECT id, created_at, updated_at, is_ca, tls_version, key_usage, not_after, not_before, 
	   ext_key_usage, serial_number, subject_key_id, authority_key_id, issuer_common_name, 
	   signature_algorithm, public_key_algorithm, crl_distribution_points, subject_common_name 
FROM tlscertificate 
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertTLSCertificate(ctx context.Context, a *oamcert.TLSCertificate) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.tls_certificate.upsert",
		SQLText: upsertTLSCertificateText,
		Args: []any{
			sql.Named("is_ca", a.IsCA),
			sql.Named("tls_version", a.Version),
			sql.Named("key_usage", strings.Join(a.KeyUsage, ",")),
			sql.Named("not_after", a.NotAfter),
			sql.Named("not_before", a.NotBefore),
			sql.Named("ext_key_usage", strings.Join(a.ExtKeyUsage, ",")),
			sql.Named("serial_number", a.SerialNumber),
			sql.Named("subject_key_id", a.SubjectKeyID),
			sql.Named("authority_key_id", a.AuthorityKeyID),
			sql.Named("issuer_common_name", a.IssuerCommonName),
			sql.Named("signature_algorithm", a.SignatureAlgorithm),
			sql.Named("subject_common_name", a.SubjectCommonName),
			sql.Named("public_key_algorithm", a.PublicKeyAlgorithm),
			sql.Named("crl_distribution_points", strings.Join(a.CRLDistributionPoints, ",")),
		},
		Result: done,
	})
	err := <-done
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.tls_certificate.entity_id_by_tls_certificate",
		SQLText: selectEntityIDByTLSCertificateText,
		Args:    []any{sql.Named("serial_number", a.SerialNumber)},
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

	var c, u string
	var row_id, version int64
	var a oamcert.TLSCertificate
	var keyusage, extkeyusage, crldp string
	if err := result.Row.Scan(&row_id, &c, &u, &a.IsCA, &version, &keyusage, &a.NotAfter, &a.NotBefore,
		&extkeyusage, &a.SerialNumber, &a.SubjectKeyID, &a.AuthorityKeyID, &a.IssuerCommonName,
		&a.SignatureAlgorithm, &a.PublicKeyAlgorithm, &crldp, &a.SubjectCommonName); err != nil {
		return nil, err
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

	if version != 0 {
		a.Version = strconv.FormatInt(version, 10)
	}

	if keyusage != "" {
		a.KeyUsage = strings.Split(keyusage, ",")
	}

	if extkeyusage != "" {
		a.ExtKeyUsage = strings.Split(extkeyusage, ",")
	}

	if crldp != "" {
		a.CRLDistributionPoints = strings.Split(crldp, ",")
	}

	return e, nil
}
