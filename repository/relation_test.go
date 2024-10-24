// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"net/netip"
	"testing"
	"time"

	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
	"github.com/stretchr/testify/assert"
)

func TestUnfilteredRelations(t *testing.T) {
	source := domain.FQDN{Name: "owasp.com"}
	dest1 := domain.FQDN{Name: "www.example.owasp.org"}
	rel1 := "cname_record"

	sourceEntity, err := store.CreateEntity(source)
	if err != nil {
		t.Fatalf("failed to create asset: %s", err)
	}

	dest1Entity, err := store.CreateEntity(dest1)
	if err != nil {
		t.Fatalf("failed to create asset: %s", err)
	}

	ip, _ := netip.ParseAddr("192.168.1.100")
	dest2 := network.IPAddress{Address: ip, Type: "IPv4"}
	rel2 := "a_record"

	dest2Entity, err := store.CreateEntity(dest2)
	if err != nil {
		t.Fatalf("failed to create asset: %s", err)
	}

	_, err = store.Link(sourceEntity, rel1, dest1Entity)
	assert.NoError(t, err)
	r2Rel, err := store.Link(sourceEntity, rel2, dest2Entity)
	assert.NoError(t, err)

	// Outgoing relations with no filter returns all outgoing relations.
	outs, err := store.OutgoingRelations(sourceEntity, time.Time{})
	assert.NoError(t, err)
	assert.Equal(t, len(outs), 2)

	// Outgoing relations with a filter returns
	outs, err = store.OutgoingRelations(sourceEntity, time.Time{}, rel1)
	assert.NoError(t, err)
	assert.Equal(t, sourceEntity.ID, outs[0].FromEntity.ID)
	assert.Equal(t, rel1, outs[0].Type)
	assert.Equal(t, dest1Entity.ID, outs[0].ToEntity.ID)

	// Incoming relations with a filter returns
	ins, err := store.IncomingRelations(dest1Entity, time.Time{}, rel1)
	assert.NoError(t, err)
	assert.Equal(t, sourceEntity.ID, ins[0].FromEntity.ID)
	assert.Equal(t, rel1, ins[0].Type)
	assert.Equal(t, dest1Entity.ID, ins[0].ToEntity.ID)

	// Outgoing with source -> a_record -> dest2Asset
	outs, err = store.OutgoingRelations(sourceEntity, time.Time{}, rel2)
	assert.NoError(t, err)
	assert.Equal(t, sourceEntity.ID, outs[0].FromEntity.ID)
	assert.Equal(t, rel2, outs[0].Type)
	assert.Equal(t, dest2Entity.ID, outs[0].ToEntity.ID)

	// Incoming for source -> a_record -> dest2asset
	ins, err = store.IncomingRelations(dest2Entity, time.Time{}, rel2)
	assert.NoError(t, err)
	assert.Equal(t, sourceEntity.ID, ins[0].FromEntity.ID)
	assert.Equal(t, rel2, ins[0].Type)
	assert.Equal(t, dest2Entity.ID, ins[0].ToEntity.ID)

	// Nanoseconds are truncated by the database; sleep for 1s
	time.Sleep(1000 * time.Millisecond)

	// Store a duplicate relation and validate last_seen is updated
	rr, err := store.Link(sourceEntity, rel2, dest2Entity)
	assert.NoError(t, err)
	assert.NotNil(t, rr)
	if rr.LastSeen.UnixNano() <= r2Rel.LastSeen.UnixNano() {
		t.Errorf("rr.LastSeen: %s, r2Rel.LastSeen: %s", rr.LastSeen.Format(time.RFC3339Nano), r2Rel.LastSeen.Format(time.RFC3339Nano))
	}
}
