// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"testing"
	"time"

	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindEntitiesByTagValue(t *testing.T) {
	db, dir, err := setupTempSQLite()
	require.NoError(t, err)
	defer teardownTempSQLite(db, dir)

	ctx := context.Background()
	txt := func(name, data string) {
		fqdn, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: name})
		require.NoError(t, err)

		_, err = db.CreateEntityProperty(ctx, fqdn, &oamdns.DNSRecordProperty{PropertyName: "dns_record",
			Header: oamdns.RRHeader{RRType: 16, Class: 1}, Data: data})
		require.NoError(t, err)
	}

	txt("owasp.org", "google-site-verification=abc123")
	txt("owasp-events.org", "google-site-verification=abc123")
	txt("example.com", "google-site-verification=zzz999")
	txt("other.example", "v=spf1 include:_spf.OWASP.org ~all")
	txt("percent.example", "v=spf1 include:a%b.example ~all")

	ents, more, err := db.FindEntitiesByTagValue(ctx, oam.FQDN, "dns_record", "google-site-verification=abc123", false,
		time.Time{}, 10)
	require.NoError(t, err)
	assert.False(t, more)

	var names []string
	for _, e := range ents {
		names = append(names, e.Asset.Key())
	}
	assert.ElementsMatch(t, []string{"owasp.org", "owasp-events.org"}, names)

	ents, _, err = db.FindEntitiesByTagValue(ctx, oam.FQDN, "dns_record", "_spf.owasp.org", true, time.Time{}, 10)
	require.NoError(t, err)
	require.Len(t, ents, 1)
	assert.Equal(t, "other.example", ents[0].Asset.Key())

	// LIKE wildcards in the value are literal.
	ents, _, err = db.FindEntitiesByTagValue(ctx, oam.FQDN, "dns_record", "a%b", true, time.Time{}, 10)
	require.NoError(t, err)
	require.Len(t, ents, 1)
	assert.Equal(t, "percent.example", ents[0].Asset.Key())

	ents, more, err = db.FindEntitiesByTagValue(ctx, oam.FQDN, "dns_record", "google-site-verification", true,
		time.Time{}, 2)
	require.NoError(t, err)
	assert.Len(t, ents, 2)
	assert.True(t, more)

	ents, _, err = db.FindEntitiesByTagValue(ctx, oam.IPAddress, "dns_record", "google-site-verification=abc123",
		false, time.Time{}, 10)
	require.NoError(t, err)
	assert.Empty(t, ents)

	_, _, err = db.FindEntitiesByTagValue(ctx, oam.FQDN, "dns_record", "", false, time.Time{}, 10)
	assert.Error(t, err)
	_, _, err = db.FindEntitiesByTagValue(ctx, oam.FQDN, "dns_record", "x", false, time.Time{}, 501)
	assert.Error(t, err)
}

func TestFindEntitiesByAttribute(t *testing.T) {
	db, dir, err := setupTempSQLite()
	require.NoError(t, err)
	defer teardownTempSQLite(db, dir)

	ctx := context.Background()
	cert := func(serial, cn, skid, akid string) {
		_, err := db.CreateAsset(ctx, &oamcert.TLSCertificate{Version: "3", SerialNumber: serial,
			SubjectCommonName: cn, IssuerCommonName: "Example CA", NotBefore: "2026-01-01T00:00:00Z",
			NotAfter: "2027-01-01T00:00:00Z", SubjectKeyID: skid, AuthorityKeyID: akid})
		require.NoError(t, err)
	}

	cert("01", "www.owasp.org", "aa:bb", "ca:01")
	cert("02", "owasp-events.org", "aa:bb", "ca:01")
	cert("03", "www.example.com", "cc:dd", "ca:02")

	ents, more, err := db.FindEntitiesByAttribute(ctx, oam.TLSCertificate, "subject_key_id", "aa:bb", false, time.Time{}, 10)
	require.NoError(t, err)
	assert.False(t, more)
	assert.Len(t, ents, 2)

	ents, _, err = db.FindEntitiesByAttribute(ctx, oam.TLSCertificate, "authority_key_id", "ca:02", false, time.Time{}, 10)
	require.NoError(t, err)
	require.Len(t, ents, 1)
	assert.Equal(t, "03", ents[0].Asset.Key())

	_, _, err = db.FindEntitiesByAttribute(ctx, oam.TLSCertificate, "subject_key_id') OR 1=1 --", "x", false, time.Time{},
		10)
	assert.Error(t, err)
	_, _, err = db.FindEntitiesByAttribute(ctx, oam.AssetType("entity; DROP TABLE entity"), "subject_key_id", "x",
		false, time.Time{}, 10)
	assert.Error(t, err)
}

func TestFindEntitiesByAttributeContains(t *testing.T) {
	db, dir, err := setupTempSQLite()
	require.NoError(t, err)
	defer teardownTempSQLite(db, dir)

	ctx := context.Background()
	service := func(id, location string) {
		_, err := db.CreateAsset(ctx, &oamplat.Service{ID: id, Type: "web-service",
			Attributes: map[string][]string{"Location": {location}, "Server": {"nginx"}}})
		require.NoError(t, err)
	}

	service("s1", "https://www.OWASP.org/landing")
	service("s2", "https://example.com/")
	ents, more, err := db.FindEntitiesByAttribute(ctx, oam.Service, "attributes", "owasp.org", true, time.Time{}, 10)
	require.NoError(t, err)
	assert.False(t, more)
	require.Len(t, ents, 1)
	assert.Equal(t, "s1", ents[0].Asset.(*oamplat.Service).ID)

	ents, _, err = db.FindEntitiesByAttribute(ctx, oam.Service, "attributes", "100%_owasp", true, time.Time{}, 10)
	require.NoError(t, err)
	assert.Empty(t, ents, "LIKE wildcards in the value must match literally")
}
