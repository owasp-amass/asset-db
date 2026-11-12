// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

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

// pagePostgres reads every page of root's out edges with the label filter.
func pagePostgres(t *testing.T, db *PostgresRepository, root *dbt.Entity, limit int, labels ...string) []string {
	t.Helper()

	var ids []string
	var after *dbt.EdgeCursor
	for pages := 0; ; pages++ {
		require.Less(t, pages, 100, "paging did not end")
		edges, next, err := db.ReadEdgesPage(context.Background(), root, "out", time.Time{}, after, limit,
			labels...)
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

func TestPostgresReadEdgesPage(t *testing.T) {
	db := valueFinderRepo(t)
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

	// Ties on updated_at, including microseconds a cursor must keep.
	tie := time.Date(2026, 1, 1, 0, 0, 0, 123456000, time.UTC)
	for i, id := range nodes {
		at := tie
		if i%3 == 0 {
			at = tie.Add(-time.Microsecond)
		}
		_, err := db.DB.ExecContext(ctx, "UPDATE public.edge SET updated_at = $1 WHERE edge_id = $2", at, id)
		require.NoError(t, err)
	}

	first, _, err := db.ReadEdgesLimited(ctx, root, "out", time.Time{}, 500, "node")
	require.NoError(t, err)
	var want []string
	for _, e := range first {
		want = append(want, e.ID)
	}
	for _, limit := range []int{1, 2, 3, 7, 500} {
		require.Equal(t, want, pagePostgres(t, db, root, limit, "node"), "limit %d", limit)
	}
	require.Len(t, pagePostgres(t, db, root, 2), 8, "unfiltered pages miss an edge")
	require.Len(t, pagePostgres(t, db, root, 2, "dns_record"), 1)

	// An edge updated during the read moves ahead of the cursor: no page
	// repeats an edge, and an unread edge that moved is not returned.
	page, next, err := db.ReadEdgesPage(ctx, root, "out", time.Time{}, nil, 3, "node")
	require.NoError(t, err)
	require.NotNil(t, next)
	moved := want[len(want)-1]
	for _, id := range []string{page[0].ID, moved} {
		_, err := db.DB.ExecContext(ctx, "UPDATE public.edge SET updated_at = $1 WHERE edge_id = $2",
			tie.Add(time.Hour), id)
		require.NoError(t, err)
	}

	seen := map[string]bool{}
	for _, e := range page {
		seen[e.ID] = true
	}
	for next != nil {
		var rest []*dbt.Edge
		rest, next, err = db.ReadEdgesPage(ctx, root, "out", time.Time{}, next, 3, "node")
		require.NoError(t, err)
		for _, e := range rest {
			require.False(t, seen[e.ID], "edge %s returned twice", e.ID)
			seen[e.ID] = true
		}
	}
	require.Len(t, seen, len(want)-1)
	require.False(t, seen[moved])

	_, _, err = db.ReadEdgesPage(ctx, root, "out", time.Time{}, &dbt.EdgeCursor{EdgeID: "1", SortKey: "y"}, 3)
	require.Error(t, err)
	_, _, err = db.ReadEdgesPage(ctx, root, "out", time.Time{}, nil, 0)
	require.Error(t, err)
}
