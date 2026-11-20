// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"sort"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CoKeyedGroups must group organizations that share a blocking key — an
// identifier reached by an "id" edge, a normalized (jurisdiction,
// registration_id), or a tag value — without scanning the whole type, and must
// normalize registration ids the way the sweep does (upper-case, whitespace
// removed) so differently formatted ids still collide.
func TestPostgresCoKeyedGroups(t *testing.T) {
	db := valueFinderRepo(t)
	ctx := context.Background()

	org := func(unique, name, jurisdiction, regID string) string {
		e, err := db.CreateAsset(ctx, &oamorg.Organization{
			ID: unique, Name: name, Jurisdiction: jurisdiction, RegistrationID: regID})
		require.NoError(t, err)
		return e.ID
	}

	// A & B share a normalized registration ("US-CA" + "123456"); C differs.
	a := org("ck-a", "Acme", "US-CA", "12 34 56")
	b := org("ck-b", "Acme Incorporated", "us-ca", "123456")
	c := org("ck-c", "Beta", "US-CA", "999")

	// A & C share one Identifier through an "id" edge; B has its own.
	identA, err := db.CreateAsset(ctx, &oamgen.Identifier{
		UniqueID: "ck-ident:shared", ID: "shared-id", Type: "domain"})
	require.NoError(t, err)
	identB, err := db.CreateAsset(ctx, &oamgen.Identifier{
		UniqueID: "ck-ident:solo", ID: "solo-id", Type: "domain"})
	require.NoError(t, err)

	idEdge := func(fromID string, to *dbt.Entity) {
		from, err := db.FindEntityById(ctx, fromID)
		require.NoError(t, err)
		_, err = db.CreateEdge(ctx, &dbt.Edge{
			Relation: &oamgen.SimpleRelation{Name: "id"}, FromEntity: from, ToEntity: to})
		require.NoError(t, err)
	}
	idEdge(a, identA)
	idEdge(c, identA)
	idEdge(b, identB)

	// A & B carry the same brand_key tag; C carries none.
	tag := func(id, value string) {
		e, err := db.FindEntityById(ctx, id)
		require.NoError(t, err)
		_, err = db.CreateEntityProperty(ctx, e,
			&oamgen.SimpleProperty{PropertyName: "brand_key", PropertyValue: value})
		require.NoError(t, err)
	}
	tag(a, "acme")
	tag(b, "acme")

	ids := func(g dbt.CoKeyGroup) []string {
		out := append([]string(nil), g.IDs...)
		sort.Strings(out)
		return out
	}
	want := func(x, y string) []string {
		out := []string{x, y}
		sort.Strings(out)
		return out
	}

	// Identifier: A & C share identA.
	groups, err := db.CoKeyedGroups(ctx, oam.Organization, dbt.CoKeyIdentifier, "", 50, time.Time{})
	require.NoError(t, err)
	require.Len(t, groups, 1)
	assert.Equal(t, want(a, c), ids(groups[0]))

	// Registration: A & B share the normalized key; its value is diagnostic.
	groups, err = db.CoKeyedGroups(ctx, oam.Organization, dbt.CoKeyRegistration, "", 50, time.Time{})
	require.NoError(t, err)
	require.Len(t, groups, 1)
	assert.Equal(t, "US-CA|123456", groups[0].Key)
	assert.Equal(t, want(a, b), ids(groups[0]))

	// Tag: A & B share brand_key=acme.
	groups, err = db.CoKeyedGroups(ctx, oam.Organization, dbt.CoKeyTag, "brand_key", 50, time.Time{})
	require.NoError(t, err)
	require.Len(t, groups, 1)
	assert.Equal(t, want(a, b), ids(groups[0]))

	// maxGroup below 2 is rejected: a group needs at least two members.
	groups, err = db.CoKeyedGroups(ctx, oam.Organization, dbt.CoKeyRegistration, "", 1, time.Time{})
	assert.Error(t, err)
	assert.Nil(t, groups)
}
