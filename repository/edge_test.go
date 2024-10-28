// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"net/netip"
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/relation"
	"github.com/stretchr/testify/assert"
)

func TestUnfilteredRelations(t *testing.T) {
	source := domain.FQDN{Name: "owasp.com"}
	dest1 := domain.FQDN{Name: "www.example.owasp.org"}

	sourceEntity, err := store.CreateEntity(source)
	if err != nil {
		t.Fatalf("failed to create asset: %s", err)
	}

	dest1Entity, err := store.CreateEntity(dest1)
	if err != nil {
		t.Fatalf("failed to create asset: %s", err)
	}

	edge1 := &types.Edge{
		Relation: relation.BasicDNSRelation{
			Name: "dns_record",
			Header: relation.RRHeader{
				RRType: 5,
				Class:  1,
				TTL:    86400,
			},
		},
		FromEntity: sourceEntity,
		ToEntity:   dest1Entity,
	}

	ip, _ := netip.ParseAddr("192.168.1.100")
	dest2 := network.IPAddress{Address: ip, Type: "IPv4"}

	dest2Entity, err := store.CreateEntity(dest2)
	if err != nil {
		t.Fatalf("failed to create asset: %s", err)
	}

	edge2 := &types.Edge{
		Relation: relation.BasicDNSRelation{
			Name: "dns_record",
			Header: relation.RRHeader{
				RRType: 1,
				Class:  1,
				TTL:    86400,
			},
		},
		FromEntity: sourceEntity,
		ToEntity:   dest2Entity,
	}

	_, err = store.Link(edge1)
	assert.NoError(t, err)
	r2Rel, err := store.Link(edge2)
	assert.NoError(t, err)

	// Outgoing relations with no filter returns all outgoing relations.
	outs, err := store.OutgoingEdges(sourceEntity, time.Time{})
	assert.NoError(t, err)
	assert.Equal(t, len(outs), 2)

	// Outgoing relations with a filter returns
	outs, err = store.OutgoingEdges(sourceEntity, time.Time{}, edge1.Relation.Label())
	assert.NoError(t, err)
	assert.Equal(t, sourceEntity.ID, outs[0].FromEntity.ID)
	assert.Equal(t, edge1.Relation.Label(), outs[0].Relation.Label())

	// Incoming relations with a filter returns
	ins, err := store.IncomingEdges(dest1Entity, time.Time{}, edge1.Relation.Label())
	assert.NoError(t, err)
	assert.Equal(t, sourceEntity.ID, ins[0].FromEntity.ID)
	assert.Equal(t, edge1.Relation.Label(), ins[0].Relation.Label())

	// Outgoing with source -> a_record -> dest2Asset
	outs, err = store.OutgoingEdges(sourceEntity, time.Time{}, edge2.Relation.Label())
	assert.NoError(t, err)
	assert.Equal(t, sourceEntity.ID, outs[0].FromEntity.ID)
	assert.Equal(t, edge2.Relation.Label(), outs[0].Relation.Label())

	// Incoming for source -> a_record -> dest2asset
	ins, err = store.IncomingEdges(dest2Entity, time.Time{}, edge2.Relation.Label())
	assert.NoError(t, err)
	assert.Equal(t, sourceEntity.ID, ins[0].FromEntity.ID)
	assert.Equal(t, edge2.Relation.Label(), ins[0].Relation.Label())

	// Nanoseconds are truncated by the database; sleep for 1s
	time.Sleep(1000 * time.Millisecond)

	// Store a duplicate relation and validate last_seen is updated
	rr, err := store.Link(edge2)
	assert.NoError(t, err)
	assert.NotNil(t, rr)
	if rr.LastSeen.UnixNano() <= r2Rel.LastSeen.UnixNano() {
		t.Errorf("rr.LastSeen: %s, r2Rel.LastSeen: %s", rr.LastSeen.Format(time.RFC3339Nano), r2Rel.LastSeen.Format(time.RFC3339Nano))
	}
}
