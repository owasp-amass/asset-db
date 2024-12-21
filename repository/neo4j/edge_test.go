// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/relation"
	"github.com/stretchr/testify/assert"
)

func TestCreateEdge(t *testing.T) {
	from, err := store.CreateEntity(&types.Entity{
		Asset: &domain.FQDN{
			Name: "create1.edge",
		},
	})
	assert.NoError(t, err)

	to, err := store.CreateEntity(&types.Entity{
		Asset: &domain.FQDN{
			Name: "create2.edge",
		},
	})
	assert.NoError(t, err)

	_, err = store.CreateEdge(&types.Edge{
		Relation:   &relation.SimpleRelation{Name: "invalid_label"},
		FromEntity: from,
		ToEntity:   to,
	})
	assert.Error(t, err)

	first, err := store.CreateEdge(&types.Edge{
		Relation:   &relation.SimpleRelation{Name: "node"},
		FromEntity: from,
		ToEntity:   to,
	})
	assert.NoError(t, err)

	time.Sleep(250 * time.Millisecond)
	second, err := store.CreateEdge(&types.Edge{
		Relation:   &relation.SimpleRelation{Name: "node"},
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
	_, err := store.FindEdgeById("bad_id")
	assert.Error(t, err)

	from, err := store.CreateEntity(&types.Entity{
		Asset: &domain.FQDN{
			Name: "find1.edge",
		},
	})
	assert.NoError(t, err)

	to, err := store.CreateEntity(&types.Entity{
		Asset: &domain.FQDN{
			Name: "find2.edge",
		},
	})
	assert.NoError(t, err)

	first, err := store.CreateEdge(&types.Edge{
		Relation:   &relation.SimpleRelation{Name: "node"},
		FromEntity: from,
		ToEntity:   to,
	})
	assert.NoError(t, err)

	second, err := store.FindEdgeById(first.ID)
	assert.NoError(t, err)
	assert.Equal(t, first.ID, second.ID)
	assert.Equal(t, first.FromEntity.ID, second.FromEntity.ID)
	assert.Equal(t, first.ToEntity.ID, second.ToEntity.ID)
}

func TestIncomingEdges(t *testing.T) {
	from, err := store.CreateEntity(&types.Entity{
		Asset: &domain.FQDN{
			Name: "incoming1.edge",
		},
	})
	assert.NoError(t, err)

	to, err := store.CreateEntity(&types.Entity{
		Asset: &domain.FQDN{
			Name: "incoming2.edge",
		},
	})
	assert.NoError(t, err)

	now := time.Now()
	for i := 1; i <= 10; i++ {
		created := now.Add(time.Duration(i*-24) * time.Hour)

		_, err := store.CreateEdge(&types.Edge{
			CreatedAt: created,
			LastSeen:  created,
			Relation: &relation.BasicDNSRelation{
				Name: "dns_record",
				Header: relation.RRHeader{
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

	_, err = store.IncomingEdges(to, time.Time{}, "invalid_label")
	assert.Error(t, err)

	edges, err := store.IncomingEdges(to, time.Time{}, "dns_record")
	assert.NoError(t, err)
	assert.Equal(t, len(edges), 10)

	for i := 1; i <= 10; i++ {
		since := now.Add(time.Duration(i*-24) * time.Hour)

		edges, err := store.IncomingEdges(to, since)
		assert.NoError(t, err)
		assert.Equal(t, len(edges), i)
	}
}

func TestOutgoingEdges(t *testing.T) {
	from, err := store.CreateEntity(&types.Entity{
		Asset: &domain.FQDN{
			Name: "outgoing1.edge",
		},
	})
	assert.NoError(t, err)

	to, err := store.CreateEntity(&types.Entity{
		Asset: &domain.FQDN{
			Name: "outgoing2.edge",
		},
	})
	assert.NoError(t, err)

	now := time.Now()
	for i := 1; i <= 10; i++ {
		created := now.Add(time.Duration(i*-24) * time.Hour)

		_, err := store.CreateEdge(&types.Edge{
			CreatedAt: created,
			LastSeen:  created,
			Relation: &relation.BasicDNSRelation{
				Name: "dns_record",
				Header: relation.RRHeader{
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

	_, err = store.OutgoingEdges(from, time.Time{}, "invalid_label")
	assert.Error(t, err)

	edges, err := store.OutgoingEdges(from, time.Time{}, "dns_record")
	assert.NoError(t, err)
	assert.Equal(t, len(edges), 10)

	for i := 1; i <= 10; i++ {
		since := now.Add(time.Duration(i*-24) * time.Hour)

		edges, err := store.OutgoingEdges(from, since)
		assert.NoError(t, err)
		assert.Equal(t, len(edges), i)
	}
}

func TestDeleteEdge(t *testing.T) {
	from, err := store.CreateEntity(&types.Entity{
		Asset: &domain.FQDN{
			Name: "delete1.edge",
		},
	})
	assert.NoError(t, err)

	to, err := store.CreateEntity(&types.Entity{
		Asset: &domain.FQDN{
			Name: "delete2.edge",
		},
	})
	assert.NoError(t, err)

	edge, err := store.CreateEdge(&types.Edge{
		Relation:   &relation.SimpleRelation{Name: "node"},
		FromEntity: from,
		ToEntity:   to,
	})
	assert.NoError(t, err)

	err = store.DeleteEdge(edge.ID)
	assert.NoError(t, err)

	_, err = store.FindEdgeById(edge.ID)
	assert.Error(t, err)
}
