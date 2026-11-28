// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The changes since a time name the entities created since then and the
// ones whose tags were, and a deletion moves the count; a deletion that
// removes nothing does not.
func TestSQLiteGraphChanges(t *testing.T) {
	db, dir, err := setupTempSQLite()
	require.NoError(t, err)
	defer teardownTempSQLite(db, dir)
	ctx := context.Background()

	a, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "changes.sqlite.example"})
	require.NoError(t, err)
	b, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "www.changes.sqlite.example"})
	require.NoError(t, err)
	edge, err := db.CreateEdge(ctx, &dbt.Edge{Relation: &oamgen.SimpleRelation{Name: "node"},
		FromEntity: a, ToEntity: b})
	require.NoError(t, err)

	start, err := db.GraphChanges(ctx, time.Time{})
	require.NoError(t, err)
	assert.Empty(t, start.EntityIDs, "no since asks for no entities")
	time.Sleep(50 * time.Millisecond)

	c, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "api.changes.sqlite.example"})
	require.NoError(t, err)
	_, err = db.CreateEntityProperty(ctx, a, &oamgen.SimpleProperty{PropertyName: "note", PropertyValue: "changed"})
	require.NoError(t, err)

	changed, err := db.GraphChanges(ctx, start.Now)
	require.NoError(t, err)
	assert.Contains(t, changed.EntityIDs, c.ID, "a new entity")
	assert.Contains(t, changed.EntityIDs, a.ID, "an entity with a new tag")
	assert.Equal(t, start.Deletions, changed.Deletions)

	require.NoError(t, db.DeleteEdge(ctx, edge.ID))
	after, err := db.GraphChanges(ctx, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, start.Deletions+1, after.Deletions, "a deletion")

	_ = db.DeleteEdge(ctx, edge.ID)
	again, err := db.GraphChanges(ctx, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, after.Deletions, again.Deletions, "a deletion that removed nothing")
}
