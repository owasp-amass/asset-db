//go:build integration

// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/platform"
	"github.com/stretchr/testify/assert"
)

func TestCreateEdge(t *testing.T) {
	ctx := context.Background()
	from, err := store.CreateEntity(ctx, &types.Entity{
		Asset: &dns.FQDN{
			Name: "create1.edge",
		},
	})
	assert.NoError(t, err)

	to, err := store.CreateEntity(ctx, &types.Entity{
		Asset: &dns.FQDN{
			Name: "create2.edge",
		},
	})
	assert.NoError(t, err)

	_, err = store.CreateEdge(ctx, &types.Edge{
		Relation:   &general.SimpleRelation{Name: "invalid_label"},
		FromEntity: from,
		ToEntity:   to,
	})
	assert.Error(t, err)

	first, err := store.CreateEdge(ctx, &types.Edge{
		Relation:   &general.SimpleRelation{Name: "node"},
		FromEntity: from,
		ToEntity:   to,
	})
	assert.NoError(t, err)

	time.Sleep(250 * time.Millisecond)
	second, err := store.CreateEdge(ctx, &types.Edge{
		Relation:   &general.SimpleRelation{Name: "node"},
		FromEntity: from,
		ToEntity:   to,
	})
	assert.NoError(t, err)
	assert.Equal(t, first.ID, second.ID)
	if first.LastSeen == second.LastSeen || second.LastSeen.Before(first.LastSeen) {
		t.Errorf("The last seen datetime was not updated")
	}
}

func TestFindEdgeById(t *testing.T) {
	ctx := context.Background()
	_, err := store.FindEdgeById(ctx, "bad_id")
	assert.Error(t, err)

	from, err := store.CreateEntity(ctx, &types.Entity{
		Asset: &dns.FQDN{
			Name: "find1.edge",
		},
	})
	assert.NoError(t, err)

	to, err := store.CreateEntity(ctx, &types.Entity{
		Asset: &dns.FQDN{
			Name: "find2.edge",
		},
	})
	assert.NoError(t, err)

	first, err := store.CreateEdge(ctx, &types.Edge{
		Relation:   &general.SimpleRelation{Name: "node"},
		FromEntity: from,
		ToEntity:   to,
	})
	assert.NoError(t, err)

	second, err := store.FindEdgeById(ctx, first.ID)
	assert.NoError(t, err)
	assert.Equal(t, first.ID, second.ID)
	assert.Equal(t, first.FromEntity.ID, second.FromEntity.ID)
	assert.Equal(t, first.ToEntity.ID, second.ToEntity.ID)
}

func TestIncomingEdges(t *testing.T) {
	ctx := context.Background()
	from, err := store.CreateEntity(ctx, &types.Entity{
		Asset: &dns.FQDN{
			Name: "incoming1.edge",
		},
	})
	assert.NoError(t, err)

	to, err := store.CreateEntity(ctx, &types.Entity{
		Asset: &dns.FQDN{
			Name: "incoming2.edge",
		},
	})
	assert.NoError(t, err)

	now := time.Now()
	for i := 1; i <= 10; i++ {
		created := now.Add(time.Duration(i*-24) * time.Hour)

		_, err := store.CreateEdge(ctx, &types.Edge{
			CreatedAt: created,
			LastSeen:  created,
			Relation: &dns.BasicDNSRelation{
				Name: "dns_record",
				Header: dns.RRHeader{
					RRType: 5,
					Class:  0,
					TTL:    i,
				},
			},
			FromEntity: from,
			ToEntity:   to,
		})
		assert.NoError(t, err)
	}

	_, err = store.IncomingEdges(ctx, to, time.Time{}, "invalid_label")
	assert.Error(t, err)

	edges, err := store.IncomingEdges(ctx, to, time.Time{}, "dns_record")
	assert.NoError(t, err)
	assert.Equal(t, len(edges), 10)

	for i := 1; i <= 10; i++ {
		since := now.Add(time.Duration(i*-24) * time.Hour)

		edges, err := store.IncomingEdges(ctx, to, since)
		assert.NoError(t, err)
		assert.Equal(t, len(edges), i)
	}
}

func TestOutgoingEdges(t *testing.T) {
	ctx := context.Background()
	from, err := store.CreateEntity(ctx, &types.Entity{
		Asset: &dns.FQDN{
			Name: "outgoing1.edge",
		},
	})
	assert.NoError(t, err)

	to, err := store.CreateEntity(ctx, &types.Entity{
		Asset: &dns.FQDN{
			Name: "outgoing2.edge",
		},
	})
	assert.NoError(t, err)

	now := time.Now()
	for i := 1; i <= 10; i++ {
		created := now.Add(time.Duration(i*-24) * time.Hour)

		_, err := store.CreateEdge(ctx, &types.Edge{
			CreatedAt: created,
			LastSeen:  created,
			Relation: &dns.BasicDNSRelation{
				Name: "dns_record",
				Header: dns.RRHeader{
					RRType: 5,
					Class:  0,
					TTL:    i,
				},
			},
			FromEntity: from,
			ToEntity:   to,
		})
		assert.NoError(t, err)
	}

	_, err = store.OutgoingEdges(ctx, from, time.Time{}, "invalid_label")
	assert.Error(t, err)

	edges, err := store.OutgoingEdges(ctx, from, time.Time{}, "dns_record")
	assert.NoError(t, err)
	assert.Equal(t, len(edges), 10)

	for i := 1; i <= 10; i++ {
		since := now.Add(time.Duration(i*-24) * time.Hour)

		edges, err := store.OutgoingEdges(ctx, from, since)
		assert.NoError(t, err)
		assert.Equal(t, len(edges), i)
	}
}

func TestDeleteEdge(t *testing.T) {
	ctx := context.Background()
	from, err := store.CreateEntity(ctx, &types.Entity{
		Asset: &dns.FQDN{
			Name: "delete1.edge",
		},
	})
	assert.NoError(t, err)

	to, err := store.CreateEntity(ctx, &types.Entity{
		Asset: &dns.FQDN{
			Name: "delete2.edge",
		},
	})
	assert.NoError(t, err)

	edge, err := store.CreateEdge(ctx, &types.Edge{
		Relation:   &general.SimpleRelation{Name: "node"},
		FromEntity: from,
		ToEntity:   to,
	})
	assert.NoError(t, err)

	err = store.DeleteEdge(ctx, edge.ID)
	assert.NoError(t, err)

	_, err = store.FindEdgeById(ctx, edge.ID)
	assert.Error(t, err)
}

// A port relation is stored under its own name (tcp_port_443) and checked
// as the taxonomy's "port" relationship, as the SQL repositories check it.
func TestCreatePortEdge(t *testing.T) {
	ctx := context.Background()
	host, err := store.CreateEntity(ctx, &types.Entity{Asset: &dns.FQDN{Name: "port.edge"}})
	assert.NoError(t, err, "create the host")

	svc, err := store.CreateEntity(ctx, &types.Entity{Asset: &platform.Service{ID: "port-edge-443",
		Type: "web-service"}})
	assert.NoError(t, err, "create the service")

	edge, err := store.CreateEdge(ctx, &types.Edge{
		Relation:   &general.PortRelation{Name: "tcp_port_443", PortNumber: 443, Protocol: "TCP"},
		FromEntity: host,
		ToEntity:   svc,
	})
	assert.NoError(t, err, "a port relation under its own name is valid")
	if assert.NotNil(t, edge, "the stored edge") {
		assert.Equal(t, "tcp_port_443", edge.Relation.Label(), "the stored name is kept")
	}

	_, err = store.CreateEdge(ctx, &types.Edge{
		Relation:   &general.PortRelation{Name: "tcp_port_443", PortNumber: 443, Protocol: "TCP"},
		FromEntity: svc,
		ToEntity:   host,
	})
	assert.Error(t, err, "a port relation from a service to a name is not in the taxonomy")
}
