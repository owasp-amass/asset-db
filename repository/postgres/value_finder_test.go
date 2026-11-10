// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// valueFinderRepo opens the database named by ASSETDB_POSTGRES_TEST_DSN,
// or a test container when it is unset.
func valueFinderRepo(t *testing.T) *PostgresRepository {
	t.Helper()

	if dsn := os.Getenv("ASSETDB_POSTGRES_TEST_DSN"); dsn != "" {
		repo, err := New("postgres", dsn)
		require.NoError(t, err)
		t.Cleanup(func() { _ = repo.Close() })
		return repo
	}

	c, repo, err := setupContainerAndPostgresRepo()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = repo.Close()
		_ = c.Terminate(context.Background())
	})
	return repo
}

func TestPostgresFindEntitiesByValue(t *testing.T) {
	db := valueFinderRepo(t)
	ctx := context.Background()
	txt := func(name, data string) {
		fqdn, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: name})
		require.NoError(t, err)

		_, err = db.CreateEntityProperty(ctx, fqdn, &oamdns.DNSRecordProperty{PropertyName: "dns_record",
			Header: oamdns.RRHeader{RRType: 16, Class: 1}, Data: data})
		require.NoError(t, err)
	}

	txt("vf-owasp.org", "google-site-verification=vf123")
	txt("vf-owasp-events.org", "google-site-verification=vf123")
	txt("vf-other.example", "v=spf1 include:_spf.VF-OWASP.org ~all")
	txt("vf-percent.example", "v=spf1 include:a%b.vf.example ~all")

	ents, more, err := db.FindEntitiesByTagValue(ctx, oam.FQDN, "dns_record", "google-site-verification=vf123", false,
		time.Time{}, 10)
	require.NoError(t, err)
	assert.False(t, more)
	assert.Len(t, ents, 2)

	ents, _, err = db.FindEntitiesByTagValue(ctx, oam.FQDN, "dns_record", "_spf.vf-owasp.org", true, time.Time{}, 10)
	require.NoError(t, err)
	require.Len(t, ents, 1)
	assert.Equal(t, "vf-other.example", ents[0].Asset.Key())

	ents, _, err = db.FindEntitiesByTagValue(ctx, oam.FQDN, "dns_record", "a%b", true, time.Time{}, 10)
	require.NoError(t, err)
	require.Len(t, ents, 1)
	assert.Equal(t, "vf-percent.example", ents[0].Asset.Key())

	ents, more, err = db.FindEntitiesByTagValue(ctx, oam.FQDN, "dns_record", "vf123", true, time.Time{}, 1)
	require.NoError(t, err)
	assert.Len(t, ents, 1)
	assert.True(t, more)

	cert := func(serial, cn, skid string) {
		_, err := db.CreateAsset(ctx, &oamcert.TLSCertificate{Version: "3", SerialNumber: serial,
			SubjectCommonName: cn, IssuerCommonName: "Example CA", NotBefore: "2026-01-01T00:00:00Z",
			NotAfter: "2027-01-01T00:00:00Z", SubjectKeyID: skid, AuthorityKeyID: "vf:ca"})
		require.NoError(t, err)
	}

	cert("vf01", "www.vf-owasp.org", "vf:aa")
	cert("vf02", "vf-owasp-events.org", "vf:aa")
	cert("vf03", "www.vf.example", "vf:cc")

	ents, _, err = db.FindEntitiesByAttribute(ctx, oam.TLSCertificate, "subject_key_id", "vf:aa", time.Time{}, 10)
	require.NoError(t, err)
	assert.Len(t, ents, 2)

	ents, _, err = db.FindEntitiesByAttribute(ctx, oam.TLSCertificate, "authority_key_id", "vf:ca", time.Time{}, 10)
	require.NoError(t, err)
	assert.Len(t, ents, 3)

	_, _, err = db.FindEntitiesByAttribute(ctx, oam.TLSCertificate, "x') OR 1=1 --", "x", time.Time{}, 10)
	assert.Error(t, err)
	_, _, err = db.FindEntitiesByAttribute(ctx, oam.AssetType("entity; DROP TABLE entity"), "subject_key_id", "x",
		time.Time{}, 10)
	assert.Error(t, err)
}
