// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"strconv"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/stretchr/testify/assert"
)

func TestCreateAssetForTLSCertificate(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	version := "3"
	serialNumber := "1234567890"
	subcommonname := "www.fake-domain.com"
	isscommonname := "Fake Issuer CA"
	notbefore := time.Now().Add(-1 * time.Hour).Format("2006-01-02T15:04:05Z07:00")
	notafter := time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02T15:04:05Z07:00")
	keyusages := []string{oamcert.KeyUsageDigitalSignature, oamcert.KeyUsageKeyEncipherment}
	extkeyusages := []string{oamcert.ExtKeyUsageServerAuth, oamcert.ExtKeyUsageClientAuth}
	sigalgorithm := "SHA256-RSA"
	pubkeyalgorithm := "RSA"
	isca := false
	crld := []string{"http://crl.fake-domain.com/fake.crl"}
	skid := "FAKE1234567890SKID"
	aki := "FAKE1234567890AKI"

	certificate, err := db.CreateAsset(ctx, &oamcert.TLSCertificate{
		Version:               version,
		SerialNumber:          serialNumber,
		SubjectCommonName:     subcommonname,
		IssuerCommonName:      isscommonname,
		NotBefore:             notbefore,
		NotAfter:              notafter,
		KeyUsage:              keyusages,
		ExtKeyUsage:           extkeyusages,
		SignatureAlgorithm:    sigalgorithm,
		PublicKeyAlgorithm:    pubkeyalgorithm,
		IsCA:                  isca,
		CRLDistributionPoints: crld,
		SubjectKeyID:          skid,
		AuthorityKeyID:        aki,
	})
	assert.NoError(t, err, "Failed to create asset for the TLSCertificate")
	assert.NotNil(t, certificate, "Entity for the TLSCertificate should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, certificate.CreatedAt, before, after, "TLSCertificate entity CreatedAt is incorrect")
	assert.WithinRange(t, certificate.LastSeen, before, after, "TLSCertificate entity LastSeen is incorrect")

	id, err := strconv.ParseInt(certificate.ID, 10, 64)
	assert.NoError(t, err, "TLSCertificate entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "TLSCertificate entity ID is not greater than zero")

	found, err := db.FindEntityById(ctx, certificate.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the TLSCertificate")
	assert.NotNil(t, found, "Entity found by ID for the TLSCertificate should not be nil")
	assert.Equal(t, certificate.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the TLSCertificate does not match")
	assert.Equal(t, certificate.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the TLSCertificate does not match")

	certificate2, ok := found.Asset.(*oamcert.TLSCertificate)
	assert.True(t, ok, "TLSCertificate found by ID is not of type *oampcert.TLSCertificate")
	assert.Equal(t, found.ID, certificate.ID, "TLSCertificate found by Entity ID does not have matching IDs")
	assert.Equal(t, certificate2.SerialNumber, serialNumber, "TLSCertificate found by ID does not have matching UniqueID")
	assert.Equal(t, certificate2.SubjectCommonName, subcommonname, "TLSCertificate found by ID does not have matching Type")
	assert.Equal(t, certificate2.IssuerCommonName, isscommonname, "TLSCertificate found by ID does not have matching Output")
	assert.Equal(t, certificate2.NotBefore, notbefore, "TLSCertificate found by ID does not have matching OutputLen")
	assert.Equal(t, certificate2.NotAfter, notafter, "TLSCertificate found by ID does not have matching Attributes")

	err = db.DeleteEntity(ctx, certificate.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the TLSCertificate")

	_, err = db.FindEntityById(ctx, certificate.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the TLSCertificate")
}

func TestFindEntitiesByContentForTLSCertificate(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	version := "3"
	serialNumber := "1234567890"
	subcommonname := "www.fake-domain.com"
	isscommonname := "Fake Issuer CA"
	notbefore := time.Now().Add(-1 * time.Hour).Format("2006-01-02T15:04:05Z07:00")
	notafter := time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02T15:04:05Z07:00")
	keyusages := []string{oamcert.KeyUsageDigitalSignature, oamcert.KeyUsageKeyEncipherment}
	extkeyusages := []string{oamcert.ExtKeyUsageServerAuth, oamcert.ExtKeyUsageClientAuth}
	sigalgorithm := "SHA256-RSA"
	pubkeyalgorithm := "RSA"
	isca := false
	crld := []string{"http://crl.fake-domain.com/fake.crl"}
	skid := "FAKE1234567890SKID"
	aki := "FAKE1234567890AKI"

	certificate, err := db.CreateAsset(ctx, &oamcert.TLSCertificate{
		Version:               version,
		SerialNumber:          serialNumber,
		SubjectCommonName:     subcommonname,
		IssuerCommonName:      isscommonname,
		NotBefore:             notbefore,
		NotAfter:              notafter,
		KeyUsage:              keyusages,
		ExtKeyUsage:           extkeyusages,
		SignatureAlgorithm:    sigalgorithm,
		PublicKeyAlgorithm:    pubkeyalgorithm,
		IsCA:                  isca,
		CRLDistributionPoints: crld,
		SubjectKeyID:          skid,
		AuthorityKeyID:        aki,
	})
	assert.NoError(t, err, "Failed to create asset for the TLSCertificate")
	assert.NotNil(t, certificate, "Entity for the TLSCertificate should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = db.FindEntitiesByContent(ctx, oam.TLSCertificate, after, 1, dbt.ContentFilters{
		"serial_number": serialNumber,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	ents, err := db.FindEntitiesByContent(ctx, oam.TLSCertificate, before, 1, dbt.ContentFilters{
		"serial_number": serialNumber,
	})
	assert.NoError(t, err, "Failed to find entity by content for the TLSCertificate")
	found := ents[0]
	assert.NotNil(t, found, "Entity found by content for the TLSCertificate should not be nil")

	certificate2, ok := found.Asset.(*oamcert.TLSCertificate)
	assert.True(t, ok, "TLSCertificate found by content is not of type *oamcert.TLSCertificate")
	assert.Equal(t, found.ID, certificate.ID, "TLSCertificate found by content does not have matching IDs")
	assert.Equal(t, certificate2.Version, version, "TLSCertificate found by content does not have matching version")
	assert.Equal(t, certificate2.SerialNumber, serialNumber, "TLSCertificate found by content does not have matching serial number")
	assert.Equal(t, certificate2.SubjectCommonName, subcommonname, "TLSCertificate found by content does not have matching subject common name")
	assert.Equal(t, certificate2.IssuerCommonName, isscommonname, "TLSCertificate found by content does not have matching issuer common name")
	assert.Equal(t, certificate2.NotBefore, notbefore, "TLSCertificate found by content does not have matching not before")
	assert.Equal(t, certificate2.NotAfter, notafter, "TLSCertificate found by content does not have matching not after")
	assert.Equal(t, certificate2.KeyUsage, keyusages, "TLSCertificate found by content does not have matching key usages")
	assert.Equal(t, certificate2.ExtKeyUsage, extkeyusages, "TLSCertificate found by content does not have matching ext key usages")
	assert.Equal(t, certificate2.SignatureAlgorithm, sigalgorithm, "TLSCertificate found by content does not have matching signature algorithm")
	assert.Equal(t, certificate2.PublicKeyAlgorithm, pubkeyalgorithm, "TLSCertificate found by content does not have matching public key algorithm")
	assert.Equal(t, certificate2.IsCA, isca, "TLSCertificate found by content does not have matching is CA")
	assert.Equal(t, certificate2.CRLDistributionPoints, crld, "TLSCertificate found by content does not have matching CRL distribution points")
	assert.Equal(t, certificate2.SubjectKeyID, skid, "TLSCertificate found by content does not have matching subject key ID")
	assert.Equal(t, certificate2.AuthorityKeyID, aki, "TLSCertificate found by content does not have matching authority key ID")

	for k, v := range map[string]string{
		"serial_number":       serialNumber,
		"subject_common_name": subcommonname,
	} {
		ents, err := db.FindEntitiesByContent(ctx, oam.TLSCertificate, before, 0, dbt.ContentFilters{k: v})
		assert.NoError(t, err, "Failed to find entities by content for the TLSCertificate")
		assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the TLSCertificate")
	}
}
