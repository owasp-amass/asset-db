// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// TLSCERTIFICATE -------------------------------------------------------------
// Params: :serial_number, :subject_common_name, :is_ca, :tls_version, :key_usage, :ext_key_usage,
//
//	:not_before, :not_after, :subject_key_id, :authority_key_id, :issuer_common_name,
//	:signature_algorithm, :public_key_algorithm, :crl_distribution_points, :attrs
const tmplUpsertTLSCertificate = `
WITH
  row_try AS (
    INSERT INTO tlscertificate(
      serial_number, subject_common_name, is_ca, tls_version, key_usage, ext_key_usage,
      not_before, not_after, subject_key_id, authority_key_id, issuer_common_name,
      signature_algorithm, public_key_algorithm, crl_distribution_points
    ) VALUES (
      :serial_number, :subject_common_name, :is_ca, :tls_version, :key_usage, :ext_key_usage,
      :not_before, :not_after, :subject_key_id, :authority_key_id, :issuer_common_name,
      :signature_algorithm, :public_key_algorithm, :crl_distribution_points
    )
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
      updated_at            = CASE WHEN
        (excluded.subject_common_name IS NOT tlscertificate.subject_common_name) OR
        (excluded.is_ca               IS NOT tlscertificate.is_ca) OR
        (excluded.tls_version         IS NOT tlscertificate.tls_version) OR
        (excluded.key_usage           IS NOT tlscertificate.key_usage) OR
        (excluded.ext_key_usage       IS NOT tlscertificate.ext_key_usage) OR
        (excluded.not_before          IS NOT tlscertificate.not_before) OR
        (excluded.not_after           IS NOT tlscertificate.not_after) OR
        (excluded.subject_key_id      IS NOT tlscertificate.subject_key_id) OR
        (excluded.authority_key_id    IS NOT tlscertificate.authority_key_id) OR
        (excluded.issuer_common_name  IS NOT tlscertificate.issuer_common_name) OR
        (excluded.signature_algorithm IS NOT tlscertificate.signature_algorithm) OR
        (excluded.public_key_algorithm IS NOT tlscertificate.public_key_algorithm) OR
        (excluded.crl_distribution_points IS NOT tlscertificate.crl_distribution_points)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE tlscertificate.updated_at END
    WHERE (excluded.subject_common_name IS NOT tlscertificate.subject_common_name) OR
          (excluded.is_ca               IS NOT tlscertificate.is_ca) OR
          (excluded.tls_version         IS NOT tlscertificate.tls_version) OR
          (excluded.key_usage           IS NOT tlscertificate.key_usage) OR
          (excluded.ext_key_usage       IS NOT tlscertificate.ext_key_usage) OR
          (excluded.not_before          IS NOT tlscertificate.not_before) OR
          (excluded.not_after           IS NOT tlscertificate.not_after) OR
          (excluded.subject_key_id      IS NOT tlscertificate.subject_key_id) OR
          (excluded.authority_key_id    IS NOT tlscertificate.authority_key_id) OR
          (excluded.issuer_common_name  IS NOT tlscertificate.issuer_common_name) OR
          (excluded.signature_algorithm IS NOT tlscertificate.signature_algorithm) OR
          (excluded.public_key_algorithm IS NOT tlscertificate.public_key_algorithm) OR
          (excluded.crl_distribution_points IS NOT tlscertificate.crl_distribution_points)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM tlscertificate WHERE serial_number=:serial_number LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('tlscertificate') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='tlscertificate' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :serial_number, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=:serial_number LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'tlscertificate',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

type TLSCertificate struct {
	ID                    int64      `json:"id"`
	CreatedAt             *time.Time `json:"created_at,omitempty"`
	UpdatedAt             *time.Time `json:"updated_at,omitempty"`
	IsCA                  *bool      `json:"is_ca,omitempty"`
	TLSVersion            *int64     `json:"tls_version,omitempty"`
	KeyUsage              *string    `json:"key_usage,omitempty"`
	NotAfter              *time.Time `json:"not_after,omitempty"`
	NotBefore             *time.Time `json:"not_before,omitempty"`
	ExtKeyUsage           *string    `json:"ext_key_usage,omitempty"`
	SerialNumber          string     `json:"serial_number"`
	SubjectKeyID          *string    `json:"subject_key_id,omitempty"`
	AuthorityKeyID        *string    `json:"authority_key_id,omitempty"`
	IssuerCommonName      *string    `json:"issuer_common_name,omitempty"`
	SignatureAlgorithm    *string    `json:"signature_algorithm,omitempty"`
	SubjectCommonName     string     `json:"subject_common_name"`
	PublicKeyAlgorithm    *string    `json:"public_key_algorithm,omitempty"`
	CRLDistributionPoints *string    `json:"crl_distribution_points,omitempty"`
}

func (s *Statements) UpsertTLSCertificate(ctx context.Context, cert *TLSCertificate, attrsJSON string) (int64, error) {
	row := s.UpsertTLSCertificateStmt.QueryRowContext(ctx,
		sql.Named("id", cert.ID),
		sql.Named("created_at", cert.CreatedAt),
		sql.Named("updated_at", cert.UpdatedAt),
		sql.Named("is_ca", cert.IsCA),
		sql.Named("tls_version", cert.TLSVersion),
		sql.Named("key_usage", cert.KeyUsage),
		sql.Named("not_after", cert.NotAfter),
		sql.Named("not_before", cert.NotBefore),
		sql.Named("ext_key_usage", cert.ExtKeyUsage),
		sql.Named("serial_number", cert.SerialNumber),
		sql.Named("subject_key_id", cert.SubjectKeyID),
		sql.Named("authority_key_id", cert.AuthorityKeyID),
		sql.Named("issuer_common_name", cert.IssuerCommonName),
		sql.Named("signature_algorithm", cert.SignatureAlgorithm),
		sql.Named("subject_common_name", cert.SubjectCommonName),
		sql.Named("public_key_algorithm", cert.PublicKeyAlgorithm),
		sql.Named("crl_distribution_points", cert.CRLDistributionPoints),
		sql.Named("attrs", attrsJSON),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchTLSCertificateByRowID(ctx context.Context, rowID int64) (*TLSCertificate, error) {
	query := `SELECT id, created_at, updated_at, is_ca, tls_version, key_usage, not_after, not_before, ext_key_usage,
		             serial_number, subject_key_id, authority_key_id, issuer_common_name, signature_algorithm,
		             public_key_algorithm, crl_distribution_points, subject_common_name
		      FROM tlscertificate WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "tlscertificates", query)
	if err != nil {
		return nil, err
	}

	var a TLSCertificate
	var c, u, na, nb *string
	var isca *int64
	var tlsver *int64
	if err := st.QueryRowContext(ctx, rowID).Scan(
		&a.ID, &c, &u, &isca, &tlsver, &a.KeyUsage, &na, &nb, &a.ExtKeyUsage,
		&a.SerialNumber, &a.SubjectKeyID, &a.AuthorityKeyID, &a.IssuerCommonName,
		&a.SignatureAlgorithm, &a.PublicKeyAlgorithm, &a.CRLDistributionPoints, &a.SubjectCommonName,
	); err != nil {
		return nil, err
	}
	if isca != nil {
		b := *isca != 0
		a.IsCA = &b
	}

	a.TLSVersion = tlsver
	a.NotAfter = parseTS(na)
	a.NotBefore = parseTS(nb)
	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	return &a, nil
}
