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

func TestSQLiteBatchReads(t *testing.T) {
	db, dir, err := setupTempSQLite()
	require.NoError(t, err)
	defer teardownTempSQLite(db, dir)
	ctx := context.Background()

	root, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "batch.example"})
	require.NoError(t, err)

	var children []*dbt.Entity
	for i := 0; i < 3; i++ {
		child, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: fmt.Sprintf("h%d.batch.example", i)})
		require.NoError(t, err)
		_, err = db.CreateEdge(ctx, &dbt.Edge{Relation: &oamgen.SimpleRelation{Name: "node"},
			FromEntity: root, ToEntity: child})
		require.NoError(t, err)
		children = append(children, child)
	}

	ip, err := db.CreateAsset(ctx, &oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.7"), Type: "IPv4"})
	require.NoError(t, err)
	_, err = db.CreateEdge(ctx, &dbt.Edge{Relation: &oamdns.BasicDNSRelation{Name: "dns_record",
		Header: oamdns.RRHeader{RRType: 1, Class: 1}}, FromEntity: root, ToEntity: ip})
	require.NoError(t, err)

	t.Run("entities by ids", func(t *testing.T) {
		ents, err := db.FindEntitiesByIds(ctx, []string{children[2].ID, ip.ID, "987654321", root.ID})
		require.NoError(t, err)
		require.Len(t, ents, 3)
		require.Equal(t, children[2].ID, ents[0].ID)
		require.Equal(t, "h2.batch.example", ents[0].Asset.(*oamdns.FQDN).Name)
		require.Equal(t, ip.ID, ents[1].ID)
		require.Equal(t, "192.0.2.7", ents[1].Asset.(*oamnet.IPAddress).Address.String())
		require.Equal(t, root.ID, ents[2].ID)

		none, err := db.FindEntitiesByIds(ctx, nil)
		require.NoError(t, err)
		require.Empty(t, none)
		_, err = db.FindEntitiesByIds(ctx, []string{"not-a-number"})
		require.Error(t, err)
	})

	t.Run("edges per label", func(t *testing.T) {
		edges, more, err := db.ReadEdgesPerLabel(ctx, root, "out", time.Time{}, 2)
		require.NoError(t, err)
		require.Equal(t, []string{"node"}, more)
		count := map[string]int{}
		for _, e := range edges {
			count[e.Relation.Label()]++
			require.Equal(t, root.ID, e.FromEntity.ID)
		}
		require.Equal(t, map[string]int{"node": 2, "dns_record": 1}, count)

		// Each label's edges are what ReadEdgesLimited returns for it alone.
		alone, _, err := db.ReadEdgesLimited(ctx, root, "out", time.Time{}, 2, "node")
		require.NoError(t, err)
		var want, got []string
		for _, e := range alone {
			want = append(want, e.ID)
		}
		for _, e := range edges {
			if e.Relation.Label() == "node" {
				got = append(got, e.ID)
			}
		}
		require.Equal(t, want, got)

		edges, more, err = db.ReadEdgesPerLabel(ctx, root, "out", time.Time{}, 5, "dns_record")
		require.NoError(t, err)
		require.Empty(t, more)
		require.Len(t, edges, 1)
		require.Equal(t, ip.ID, edges[0].ToEntity.ID)

		in, more, err := db.ReadEdgesPerLabel(ctx, children[0], "in", time.Time{}, 5)
		require.NoError(t, err)
		require.Empty(t, more)
		require.Len(t, in, 1)
		require.Equal(t, root.ID, in[0].FromEntity.ID)

		_, _, err = db.ReadEdgesPerLabel(ctx, root, "sideways", time.Time{}, 5)
		require.Error(t, err)
	})
}
