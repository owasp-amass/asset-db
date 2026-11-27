// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"fmt"
	"testing"

	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Degree histograms count, per label, how many entities have each number of
// edges in a direction.
func TestSQLiteDegreeHistograms(t *testing.T) {
	db, dir, err := setupTempSQLite()
	require.NoError(t, err)
	defer teardownTempSQLite(db, dir)
	ctx := context.Background()

	fqdn := func(name string) *dbt.Entity {
		e, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: name})
		require.NoError(t, err)
		return e
	}
	var src []*dbt.Entity
	for i := range 3 {
		src = append(src, fqdn(fmt.Sprintf("s%d.degrees.example", i)))
	}
	hub, one, two := fqdn("hub.degrees.example"), fqdn("one.degrees.example"), fqdn("two.degrees.example")
	link := func(from, to *dbt.Entity) {
		_, err := db.CreateEdge(ctx, &dbt.Edge{Relation: &oamgen.SimpleRelation{Name: "node"},
			FromEntity: from, ToEntity: to})
		require.NoError(t, err)
	}
	// the hub has three edges in; one and two have one each
	for _, s := range src {
		link(s, hub)
	}
	link(src[0], one)
	link(src[1], two)

	in, err := db.DegreeHistograms(ctx, "in", []string{"NODE", "nothing"})
	require.NoError(t, err)
	assert.Equal(t, map[string]dbt.DegreeHistogram{"node": {1: 2, 3: 1}}, in,
		"labels match without case, and a label no edge has is absent")
	out, err := db.DegreeHistograms(ctx, "out", []string{"node"})
	require.NoError(t, err)
	assert.Equal(t, map[string]dbt.DegreeHistogram{"node": {1: 1, 2: 2}}, out)

	_, err = db.DegreeHistograms(ctx, "both", []string{"node"})
	assert.Error(t, err, "only in or out is counted")
	_, err = db.DegreeHistograms(ctx, "in", nil)
	assert.Error(t, err, "a read names a label")
}
