// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/stretchr/testify/require"
)

// zeroTime reads edges regardless of when they were last seen.
var zeroTime time.Time

// setEdgeUpdated stores an edge's updated_at text through the write
// worker, which holds the only write connection.
func setEdgeUpdated(t *testing.T, db *SqliteRepository, id, at string) {
	t.Helper()

	done := make(chan error, 1)
	db.ww.Submit(&writeJob{Ctx: context.Background(), Name: "test.edge.updated_at",
		SQLText: "UPDATE edge SET updated_at = ? WHERE edge_id = ?", Args: []any{at, id}, Result: done})
	require.NoError(t, <-done)
}

// pageAll reads every page of root's out edges with the label filter.
func pageAll(t *testing.T, db *SqliteRepository, root *dbt.Entity, limit int, labels ...string) []string {
	t.Helper()

	var ids []string
	var after *dbt.EdgeCursor
	for pages := 0; ; pages++ {
		require.Less(t, pages, 100, "paging did not end")
		edges, next, err := db.ReadEdgesPage(context.Background(), root, "out", zeroTime, after, limit, labels...)
		require.NoError(t, err)
		require.LessOrEqual(t, len(edges), limit)
		for _, e := range edges {
			ids = append(ids, e.ID)
		}
		if next == nil {
			return ids
		}
		after = next
	}
}

func TestReadEdgesPage(t *testing.T) {
	db, dir, err := setupTempSQLite()
	require.NoError(t, err)
	defer teardownTempSQLite(db, dir)

	ctx := context.Background()
	root, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "pages.example"})
	require.NoError(t, err)

	var nodes []string
	for i := 0; i < 7; i++ {
		child, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: fmt.Sprintf("h%d.pages.example", i)})
		require.NoError(t, err)

		e, err := db.CreateEdge(ctx, &dbt.Edge{Relation: &oamgen.SimpleRelation{Name: "node"},
			FromEntity: root, ToEntity: child})
		require.NoError(t, err)
		nodes = append(nodes, e.ID)
	}

	ip, err := db.CreateAsset(ctx, &oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.1"), Type: "IPv4"})
	require.NoError(t, err)
	_, err = db.CreateEdge(ctx, &dbt.Edge{Relation: &oamdns.BasicDNSRelation{Name: "dns_record",
		Header: oamdns.RRHeader{RRType: 1, Class: 1}}, FromEntity: root, ToEntity: ip})
	require.NoError(t, err)

	// Ties on updated_at, in both formats SQLite stores: inserts write
	// milliseconds, the content trigger writes CURRENT_TIMESTAMP.
	for i, id := range nodes {
		at := "2026-01-01 00:00:00.000"
		if i%3 == 0 {
			at = "2026-01-01 00:00:00"
		}
		setEdgeUpdated(t, db, id, at)
	}

	// Pages follow ReadEdgesLimited's order exactly, without gaps or repeats.
	first, _, err := db.ReadEdgesLimited(ctx, root, "out", zeroTime, 500, "node")
	require.NoError(t, err)
	var want []string
	for _, e := range first {
		want = append(want, e.ID)
	}
	for _, limit := range []int{1, 2, 3, 7, 500} {
		require.Equal(t, want, pageAll(t, db, root, limit, "node"), "limit %d", limit)
	}
	require.Len(t, pageAll(t, db, root, 2), 8, "unfiltered pages miss an edge")
	require.Len(t, pageAll(t, db, root, 2, "dns_record"), 1)

	// An edge updated during the read moves ahead of the cursor: no page
	// repeats an edge, and an unread edge that moved is not returned.
	page, next, err := db.ReadEdgesPage(ctx, root, "out", zeroTime, nil, 3, "node")
	require.NoError(t, err)
	require.NotNil(t, next)
	moved := want[len(want)-1]
	for _, id := range []string{page[0].ID, moved} {
		setEdgeUpdated(t, db, id, "2026-06-01 00:00:00.000")
	}

	seen := map[string]bool{}
	for _, e := range page {
		seen[e.ID] = true
	}
	for next != nil {
		var rest []*dbt.Edge
		rest, next, err = db.ReadEdgesPage(ctx, root, "out", zeroTime, next, 3, "node")
		require.NoError(t, err)
		for _, e := range rest {
			require.False(t, seen[e.ID], "edge %s returned twice", e.ID)
			seen[e.ID] = true
		}
	}
	require.Len(t, seen, len(want)-1)
	require.False(t, seen[moved])

	_, _, err = db.ReadEdgesPage(ctx, root, "out", zeroTime, &dbt.EdgeCursor{EdgeID: "x", SortKey: "y"}, 3)
	require.Error(t, err)
	_, _, err = db.ReadEdgesPage(ctx, root, "out", zeroTime, nil, 501)
	require.Error(t, err)
	_, _, err = db.ReadEdgesPage(ctx, root, "sideways", zeroTime, nil, 3)
	require.Error(t, err)
}
