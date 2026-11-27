// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"testing"

	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A value histogram counts how many entities hold each exact value, only of
// the values starting with the prefixes asked for.
func TestPostgresValueHistograms(t *testing.T) {
	db := valueFinderRepo(t)
	ctx := context.Background()
	txt := func(name, data string) {
		fqdn, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: name})
		require.NoError(t, err)
		_, err = db.CreateEntityProperty(ctx, fqdn, &oamdns.DNSRecordProperty{PropertyName: "dns_record",
			Header: oamdns.RRHeader{RRType: 16, Class: 1}, Data: data})
		require.NoError(t, err)
	}
	// one token on three names, another on one, and a record of another kind
	txt("h1.histo.example", "histo-verify=shared")
	txt("h2.histo.example", "histo-verify=shared")
	txt("h3.histo.example", "histo-verify=shared")
	txt("h4.histo.example", "HISTO-VERIFY=alone")
	txt("h5.histo.example", "v=spf1 include:histo.example ~all")

	h, err := db.TagValueHistogram(ctx, oam.FQDN, "dns_record", []string{"histo-verify="})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, h[3], int64(1), "the shared token: %v", h)
	assert.GreaterOrEqual(t, h[1], int64(1), "the token on one name, matched without case: %v", h)

	cert := func(serial, skid string) {
		_, err := db.CreateAsset(ctx, &oamcert.TLSCertificate{Version: "3", SerialNumber: serial,
			SubjectCommonName: serial + ".histo.example", IssuerCommonName: "Histo CA",
			NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z", SubjectKeyID: skid})
		require.NoError(t, err)
	}
	cert("histo01", "histo:aa")
	cert("histo02", "histo:aa")
	cert("histo03", "histo:bb")

	h, err = db.AttributeValueHistogram(ctx, oam.TLSCertificate, "subject_key_id")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, h[2], int64(1), "the shared key: %v", h)

	_, err = db.AttributeValueHistogram(ctx, oam.TLSCertificate, "x') OR 1=1 --")
	assert.Error(t, err, "an attribute key that is not an identifier")
	_, err = db.TagValueHistogram(ctx, oam.FQDN, "dns_record", []string{""})
	assert.Error(t, err, "an empty prefix")
}
