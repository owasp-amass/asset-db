// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// EntitiesPage must walk every entity of a type in entity_id-ascending keyset
// pages, returning each once and stopping with a nil cursor.
func TestPostgresEntitiesPage(t *testing.T) {
	db := valueFinderRepo(t)
	ctx := context.Background()

	want := map[string]bool{}
	for _, name := range []string{"ep-alpha", "ep-beta", "ep-gamma", "ep-delta", "ep-epsilon"} {
		e, err := db.CreateAsset(ctx, &oamorg.Organization{ID: "ep:" + name, Name: name})
		require.NoError(t, err)
		want[e.ID] = true
	}

	seen := map[string]bool{}
	var last int64 = -1
	var after *dbt.EntityCursor
	pages := 0
	for {
		ents, next, err := db.EntitiesPage(ctx, oam.Organization, time.Time{}, after, 2)
		require.NoError(t, err)
		for _, e := range ents {
			assert.False(t, seen[e.ID], "entity %s returned twice", e.ID)
			seen[e.ID] = true

			id := parseID(t, e.ID)
			assert.Greater(t, id, last, "entity_id not strictly ascending")
			last = id
		}
		pages++
		require.LessOrEqual(t, pages, 10000, "pager did not terminate")
		if next == nil {
			assert.LessOrEqual(t, len(ents), 2)
			break
		}
		assert.Len(t, ents, 2, "a non-final page must be full")
		after = next
	}

	for id := range want {
		assert.True(t, seen[id], "entity %s was never paged", id)
	}

	// A limit outside 1..1000 is rejected.
	_, _, err := db.EntitiesPage(ctx, oam.Organization, time.Time{}, nil, 0)
	assert.Error(t, err)
}

func parseID(t *testing.T, s string) int64 {
	t.Helper()
	var n int64
	for _, r := range s {
		require.True(t, r >= '0' && r <= '9', "entity id %q is not numeric", s)
		n = n*10 + int64(r-'0')
	}
	return n
}
