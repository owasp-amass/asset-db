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
	"github.com/stretchr/testify/assert"
)

// A step read returns the edges its steps follow from the entities, each
// once, forward from an edge's source and backward from its destination, and
// none that no step matches.
func TestSQLiteReadSteps(t *testing.T) {
	db, dir, err := setupTempSQLite()
	if !assert.NoError(t, err, "opening a temporary SQLite database") {
		return
	}

	defer teardownTempSQLite(db, dir)
	ctx := context.Background()

	root, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "steps.example"})
	if !assert.NoError(t, err, "creating the root FQDN") {
		return
	}

	var children []*dbt.Entity
	for i := 0; i < 3; i++ {
		child, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: fmt.Sprintf("h%d.steps.example", i)})
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

	ip, err := db.CreateAsset(ctx, &oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.9"), Type: "IPv4"})
	if !assert.NoError(t, err, "creating the IP address") {
		return
	}

	_, err = db.CreateEdge(ctx, &dbt.Edge{Relation: &oamdns.BasicDNSRelation{Name: "dns_record",
		Header: oamdns.RRHeader{RRType: 1, Class: 1}}, FromEntity: root, ToEntity: ip})
	if !assert.NoError(t, err, "linking the IP address") {
		return
	}

	down := dbt.Step{FromType: "FQDN", Label: "node", RelationType: "SimpleRelation", ToType: "FQDN", Forward: true}
	resolver := dbt.Step{FromType: "fqdn", Label: "DNS_RECORD", RelationType: "basicdnsrelation", ToType: "ipaddress"}
	steps := []dbt.Step{down, resolver}

	edges, err := db.ReadSteps(ctx, []string{root.ID}, steps, time.Time{})
	if assert.NoError(t, err) && assert.Len(t, edges, 3, "the node edges only: dns_record is followed backward") {
		for _, e := range edges {
			assert.Equal(t, root.ID, e.FromEntity.ID)
			assert.Equal(t, "node", e.Relation.Label())
		}
	}

	edges, err = db.ReadSteps(ctx, []string{ip.ID}, steps, time.Time{})
	if assert.NoError(t, err) && assert.Len(t, edges, 1, "backward from the address to the name") {
		assert.Equal(t, root.ID, edges[0].FromEntity.ID)
		assert.Equal(t, ip.ID, edges[0].ToEntity.ID)
		assert.Equal(t, "dns_record", edges[0].Relation.Label())
	}

	edges, err = db.ReadSteps(ctx, []string{root.ID, children[0].ID, ip.ID}, steps, time.Time{})
	if assert.NoError(t, err) {
		assert.Len(t, edges, 4, "each edge once, though both its ends are read")
	}

	edges, err = db.ReadSteps(ctx, []string{children[1].ID}, steps, time.Time{})
	if assert.NoError(t, err) {
		assert.Empty(t, edges, "a node edge is not followed back up to its parent")
	}

	_, err = db.ReadSteps(ctx, []string{root.ID}, nil, time.Time{})
	assert.Error(t, err, "a read without steps")
	_, err = db.ReadSteps(ctx, []string{"x"}, steps, time.Time{})
	assert.Error(t, err, "an ID that is not one")
}
