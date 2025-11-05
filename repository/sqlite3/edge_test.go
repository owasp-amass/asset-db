// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"net/netip"
	"strconv"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/stretchr/testify/assert"
)

func TestCreateEdge(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	fqdn, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "owasp.org"})
	assert.NoError(t, err, "Failed to create asset for the FQDN")
	assert.NotNil(t, fqdn, "Entity for the FQDN should not be nil")

	ip, err := db.CreateAsset(ctx, &oamnet.IPAddress{
		Address: netip.MustParseAddr("104.20.44.163"),
		Type:    "IPv4",
	})
	assert.NoError(t, err, "Failed to create asset for the IPAddress")
	assert.NotNil(t, ip, "Entity for the IPAddress should not be nil")

	rel := &oamdns.BasicDNSRelation{
		Name: "dns_record",
		Header: oamdns.RRHeader{
			RRType: 1,
			Class:  1,
			TTL:    3200,
		},
	}
	edge, err := db.CreateEdge(ctx, &dbt.Edge{
		Relation:   rel,
		FromEntity: fqdn,
		ToEntity:   ip,
	})
	assert.NoError(t, err, "Failed to create edge for the DNS record")
	assert.NotNil(t, edge, "Edge should not be nil")

	id, err := strconv.ParseInt(edge.ID, 10, 64)
	assert.NoError(t, err, "Edge ID is not a valid integer")
	assert.Greater(t, id, int64(0), "Edge ID is not greater than zero")

	found, err := db.FindEdgeById(ctx, edge.ID)
	assert.NoError(t, err, "Failed to find edge by ID")
	assert.NotNil(t, found, "Edge found by ID should not be nil")
	assert.Equal(t, edge.CreatedAt, found.CreatedAt, "Edge CreatedAt found by ID does not match")
	assert.Equal(t, edge.LastSeen, found.LastSeen, "Edge LastSeen found by ID does not match")
	assert.Equal(t, edge.FromEntity.ID, found.FromEntity.ID, "Edge found by ID does not have matching FromEntity IDs")
	assert.Equal(t, edge.ToEntity.ID, found.ToEntity.ID, "Edge found by ID does not have matching ToEntity IDs")

	rel2, ok := found.Relation.(*oamdns.BasicDNSRelation)
	assert.True(t, ok, "Edge found by ID does not have a type of *oamdns.BasicDNSRelation")
	assert.Equal(t, rel.Label(), rel2.Label(), "Edge/Relation found by ID does not have matching Labels")
	assert.Equal(t, rel.Header.RRType, rel2.Header.RRType, "Edge/Relation found by ID does not have a matching Header.RRType")
	assert.Equal(t, rel.Header.Class, rel2.Header.Class, "Edge/Relation found by ID does not have a matching Header.Class")
	assert.Equal(t, rel.Header.TTL, rel2.Header.TTL, "Edge/Relation found by ID does not have a matching Header.TTL")

	err = db.DeleteEntity(ctx, fqdn.ID)
	assert.NoError(t, err, "Failed to delete FQDN by ID")

	_, err = db.FindEdgeById(ctx, edge.ID)
	assert.Error(t, err, "Expected error when finding edge removed by cascading deletion")
}
