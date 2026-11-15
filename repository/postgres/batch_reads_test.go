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
	"github.com/stretchr/testify/assert"
)

func TestPostgresBatchReads(t *testing.T) {
	db := valueFinderRepo(t)
	ctx := context.Background()

	root, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "batch.example"})
	if !assert.NoError(t, err, "creating the root FQDN") {
		return
	}

	var children []*dbt.Entity
	for i := 0; i < 3; i++ {
		child, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: fmt.Sprintf("h%d.batch.example", i)})
		if !assert.NoError(t, err, "creating child FQDN %d", i) {
			return
		}

		_, err = db.CreateEdge(ctx, &dbt.Edge{Relation: &oamgen.SimpleRelation{Name: "node"},
			FromEntity: root, ToEntity: child})
		if !assert.NoError(t, err, "linking child FQDN %d", i) {
			return
		}

		children = append(children, child)
	}

	ip, err := db.CreateAsset(ctx, &oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.7"), Type: "IPv4"})
	if !assert.NoError(t, err, "creating the IP address") {
		return
	}

	_, err = db.CreateEdge(ctx, &dbt.Edge{Relation: &oamdns.BasicDNSRelation{Name: "dns_record",
		Header: oamdns.RRHeader{RRType: 1, Class: 1}}, FromEntity: root, ToEntity: ip})
	if !assert.NoError(t, err, "linking the IP address") {
		return
	}

	t.Run("entities by ids", func(t *testing.T) {
		ents, err := db.FindEntitiesByIds(ctx, []string{children[2].ID, ip.ID, "987654321", root.ID})
		assert.NoError(t, err, "reading entities by ID")
		if assert.Len(t, ents, 3, "an ID with no entity is left out") {
			assert.Equal(t, children[2].ID, ents[0].ID, "entities come in the order of the IDs")
			assert.Equal(t, "h2.batch.example", ents[0].Asset.(*oamdns.FQDN).Name, "the FQDN asset is read")
			assert.Equal(t, ip.ID, ents[1].ID, "entities come in the order of the IDs")
			assert.Equal(t, "192.0.2.7", ents[1].Asset.(*oamnet.IPAddress).Address.String(),
				"the IP address asset is read")
			assert.Equal(t, root.ID, ents[2].ID, "entities come in the order of the IDs")
		}

		none, err := db.FindEntitiesByIds(ctx, nil)
		assert.NoError(t, err, "reading no IDs")
		assert.Empty(t, none, "no IDs read no entities")

		_, err = db.FindEntitiesByIds(ctx, []string{"not-a-number"})
		assert.Error(t, err, "an invalid ID is refused")
	})

	t.Run("edges per label", func(t *testing.T) {
		edges, more, err := db.ReadEdgesPerLabel(ctx, root, "out", time.Time{}, 2)
		assert.NoError(t, err, "reading two edges per label")
		assert.Equal(t, []string{"node"}, more, "only the node label has more than two edges")

		count := map[string]int{}
		for _, e := range edges {
			count[e.Relation.Label()]++
			assert.Equal(t, root.ID, e.FromEntity.ID, "every out edge starts at the root")
		}

		assert.Equal(t, map[string]int{"node": 2, "dns_record": 1}, count, "each label is capped on its own")

		// Each label's edges are what ReadEdgesLimited returns for it alone.
		alone, _, err := db.ReadEdgesLimited(ctx, root, "out", time.Time{}, 2, "node")
		assert.NoError(t, err, "reading the node label alone")

		var want, got []string
		for _, e := range alone {
			want = append(want, e.ID)
		}
		for _, e := range edges {
			if e.Relation.Label() == "node" {
				got = append(got, e.ID)
			}
		}

		assert.Equal(t, want, got, "a label's edges match ReadEdgesLimited for that label")

		edges, more, err = db.ReadEdgesPerLabel(ctx, root, "out", time.Time{}, 5, "dns_record")
		assert.NoError(t, err, "reading one named label")
		assert.Empty(t, more, "the dns_record label has no more edges")
		if assert.Len(t, edges, 1, "only the named label is read") {
			assert.Equal(t, ip.ID, edges[0].ToEntity.ID, "the dns_record edge leads to the IP address")
		}

		in, more, err := db.ReadEdgesPerLabel(ctx, children[0], "in", time.Time{}, 5)
		assert.NoError(t, err, "reading in edges")
		assert.Empty(t, more, "a child has one in edge")
		if assert.Len(t, in, 1, "a child has one in edge") {
			assert.Equal(t, root.ID, in[0].FromEntity.ID, "the in edge starts at the root")
		}

		_, _, err = db.ReadEdgesPerLabel(ctx, root, "sideways", time.Time{}, 5)
		assert.Error(t, err, "an invalid direction is refused")
	})
}

// TestPostgresEntitiesByIdsQueries runs every asset type's query, so each
// one parses and its columns exist.
func TestPostgresEntitiesByIdsQueries(t *testing.T) {
	db := valueFinderRepo(t)
	assert.Len(t, entitiesByIdsReaders, 21, "every asset type has a batch query")

	for etype, reader := range entitiesByIdsReaders {
		ents, err := reader.scan(db, context.Background(), reader.query, map[string]any{"ids": []int64{-1}})
		assert.NoError(t, err, "the %s batch query runs", etype)
		assert.Empty(t, ents, "no %s entity has ID -1", etype)
	}
}
