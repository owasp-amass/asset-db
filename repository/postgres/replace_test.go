// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"testing"

	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"github.com/stretchr/testify/require"
)

func TestPostgresReplaceOrganizationClearsFields(t *testing.T) {
	db := valueFinderRepo(t)

	ctx := context.Background()
	created, err := db.CreateAsset(ctx, &oamorg.Organization{ID: "replace-apple:1", Name: "apple", LegalName: "apple 12",
		Jurisdiction: "FR", RegistrationID: "532672227", FoundingDate: "2011-06-01", Industry: "retail",
		Headcount: 10, Active: true})
	require.NoError(t, err)

	replaced, err := db.ReplaceAsset(ctx, &oamorg.Organization{ID: "replace-apple:1", Name: "apple", Active: true})
	require.NoError(t, err)
	require.Equal(t, created.ID, replaced.ID)

	got, err := db.FindEntityById(ctx, created.ID)
	require.NoError(t, err)
	o := got.Asset.(*oamorg.Organization)
	require.Equal(t, "apple", o.Name)
	require.Empty(t, o.LegalName)
	require.Empty(t, o.Jurisdiction)
	require.Empty(t, o.RegistrationID)
	require.Empty(t, o.FoundingDate)
	require.Empty(t, o.Industry)
	require.Zero(t, o.Headcount)
	require.True(t, o.Active)

	_, err = db.ReplaceAsset(ctx, &oamorg.Organization{ID: "replace-missing:1", Name: "missing"})
	require.Error(t, err, "a replacement created an organization")
	_, err = db.ReplaceAsset(ctx, &oamdns.FQDN{Name: "replace-owasp.org"})
	require.Error(t, err)
}
