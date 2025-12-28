// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"log"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/repository/postgres/testhelpers"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PostgresEdgeTestSuite struct {
	suite.Suite
	container *testhelpers.PostgresContainer
	db        *PostgresRepository
}

func TestPostgresEdgeTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresEdgeTestSuite))
}

func (suite *PostgresEdgeTestSuite) SetupSuite() {
	var err error
	suite.container, suite.db, err = setupContainerAndPostgresRepo()
	if err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresEdgeTestSuite) TearDownSuite() {
	if err := suite.container.Terminate(context.Background()); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func (suite *PostgresEdgeTestSuite) TestCreateEdge() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	fqdn, err := suite.db.CreateAsset(ctx, &oamdns.FQDN{Name: "owasp.org"})
	assert.NoError(t, err, "Failed to create asset for the FQDN")
	assert.NotNil(t, fqdn, "Entity for the FQDN should not be nil")

	ip, err := suite.db.CreateAsset(ctx, &oamnet.IPAddress{
		Address: netip.MustParseAddr("104.20.44.163"),
		Type:    "IPv4",
	})
	assert.NoError(t, err, "Failed to create asset for the IPAddress")
	assert.NotNil(t, ip, "Entity for the IPAddress should not be nil")

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	rel := &oamdns.BasicDNSRelation{
		Name: "dns_record",
		Header: oamdns.RRHeader{
			RRType: 1,
			Class:  1,
			TTL:    3200,
		},
	}
	edge, err := suite.db.CreateEdge(ctx, &dbt.Edge{
		Relation:   rel,
		FromEntity: fqdn,
		ToEntity:   ip,
	})
	assert.NoError(t, err, "Failed to create edge for the DNS record")
	assert.NotNil(t, edge, "Edge should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	// check the validity of all three IDs
	for k, v := range map[string]string{
		"edge":            edge.ID,
		"edge.FromEntity": edge.FromEntity.ID,
		"edge.ToEntity":   edge.ToEntity.ID,
	} {
		id, err := strconv.ParseInt(v, 10, 64)
		assert.NoError(t, err, k+" ID is not a valid integer")
		assert.Greater(t, id, int64(0), k+" ID is not greater than zero")
	}

	found, err := suite.db.FindEdgeById(ctx, edge.ID)
	assert.NoError(t, err, "Failed to find edge by ID")
	assert.NotNil(t, found, "Edge found by ID should not be nil")

	// check the validity of all three IDs
	for k, v := range map[string]string{
		"found":            found.ID,
		"found.FromEntity": found.FromEntity.ID,
		"found.ToEntity":   found.ToEntity.ID,
	} {
		id, err := strconv.ParseInt(v, 10, 64)
		assert.NoError(t, err, k+" ID is not a valid integer")
		assert.Greater(t, id, int64(0), k+" ID is not greater than zero")
	}

	assert.WithinRange(t, edge.CreatedAt, before, after)
	assert.WithinRange(t, edge.LastSeen, before, after)
	assert.WithinRange(t, found.CreatedAt, before, after)
	assert.WithinRange(t, found.LastSeen, before, after)
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

	err = suite.db.DeleteEntity(ctx, fqdn.ID)
	assert.NoError(t, err, "Failed to delete FQDN by ID")

	_, err = suite.db.FindEdgeById(ctx, edge.ID)
	assert.Error(t, err, "Expected error when finding edge removed by cascading deletion")
}

func (suite *PostgresEdgeTestSuite) TestIncomingEdges() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before1 := time.Now()
	time.Sleep(100 * time.Millisecond)
	fqdn1, err := suite.db.CreateAsset(ctx, &oamdns.FQDN{Name: "owasp.org"})
	assert.NoError(t, err, "Failed to create asset for the FQDN")
	assert.NotNil(t, fqdn1, "Entity for the FQDN should not be nil")

	fqdn2, err := suite.db.CreateAsset(ctx, &oamdns.FQDN{Name: "www.owasp.org"})
	assert.NoError(t, err, "Failed to create asset for the FQDN")
	assert.NotNil(t, fqdn2, "Entity for the FQDN should not be nil")

	rel1 := &oamdns.BasicDNSRelation{
		Name: "dns_record",
		Header: oamdns.RRHeader{
			RRType: 5,
			Class:  1,
			TTL:    3200,
		},
	}
	edge1, err := suite.db.CreateEdge(ctx, &dbt.Edge{
		Relation:   rel1,
		FromEntity: fqdn1,
		ToEntity:   fqdn2,
	})
	assert.NoError(t, err, "Failed to create edge for the simple relation")
	assert.NotNil(t, edge1, "Edge should not be nil")
	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()

	time.Sleep(2 * time.Second)
	before2 := time.Now()
	time.Sleep(100 * time.Millisecond)

	rel2 := &oamgen.SimpleRelation{Name: "node"}
	edge2, err := suite.db.CreateEdge(ctx, &dbt.Edge{
		Relation:   rel2,
		FromEntity: fqdn1,
		ToEntity:   fqdn2,
	})
	assert.NoError(t, err, "Failed to create edge for the simple relation")
	assert.NotNil(t, edge2, "Edge should not be nil")
	time.Sleep(100 * time.Millisecond)
	after2 := time.Now()

	tests := map[string]struct {
		entity *dbt.Entity
		before time.Time
		after  time.Time
		since  time.Time
		labels []string
		count  int
	}{
		"fqdn2": {
			entity: fqdn2,
			before: before1,
			after:  after2,
			since:  time.Time{},
			labels: []string{"dns_record", "node"},
			count:  2,
		},
		"fqdn2 since before1": {
			entity: fqdn2,
			before: before1,
			after:  after2,
			since:  before1,
			labels: nil,
			count:  2,
		},
		"fqdn2 since before2": {
			entity: fqdn2,
			before: before2,
			after:  after2,
			since:  before2,
			count:  1,
		},
		"fqdn2 since after2": {
			entity: fqdn2,
			before: before1,
			after:  after1,
			since:  after2,
			count:  0,
		},
		"fqdn2 with label dns_record": {
			entity: fqdn2,
			before: before1,
			after:  after1,
			since:  time.Time{},
			labels: []string{"dns_record"},
			count:  1,
		},
		"fqdn2 with label node": {
			entity: fqdn2,
			before: before2,
			after:  after2,
			since:  time.Time{},
			labels: []string{"node"},
			count:  1,
		},
	}

	for tname, test := range tests {
		edges, err := suite.db.IncomingEdges(ctx, test.entity, test.since, test.labels...)
		if test.count == 0 {
			assert.Error(t, err, "Expected error for "+tname)
			continue
		} else {
			assert.NoError(t, err, "Failed to get incoming edges for "+tname)
			assert.Len(t, edges, test.count, "Unexpected number of incoming edges for "+tname)
		}

		for _, edge := range edges {
			id, err := strconv.ParseInt(edge.ID, 10, 64)
			assert.NoError(t, err, "Edge ID is not a valid integer")
			assert.Greater(t, id, int64(0), "Edge ID is not greater than zero")
			assert.Equal(t, test.entity.ID, edge.ToEntity.ID, "Edge ToEntity ID does not match for "+tname)
			assert.Equal(t, fqdn1.ID, edge.FromEntity.ID, "Edge FromEntity ID does not match for "+tname)
			assert.WithinRange(t, edge.CreatedAt, test.before, test.after, "Edge CreateAt does not fall within range for "+tname)
			assert.WithinRange(t, edge.LastSeen, test.before, test.after, "Edge LastSeen does not fall within range for "+tname)

			switch rel := edge.Relation.(type) {
			case *oamdns.BasicDNSRelation:
				assert.Equal(t, rel1.Label(), rel.Label(), "Edge/Relation does not have a matching label for "+tname)
				assert.Equal(t, rel.Header.RRType, rel1.Header.RRType, "Edge/Relation found by ID does not have a matching Header.RRType")
				assert.Equal(t, rel.Header.Class, rel1.Header.Class, "Edge/Relation found by ID does not have a matching Header.Class")
				assert.Equal(t, rel.Header.TTL, rel1.Header.TTL, "Edge/Relation found by ID does not have a matching Header.TTL")
			case *oamgen.SimpleRelation:
				assert.Equal(t, rel2.Label(), rel.Label(), "Edge/Relation does not have a matching label for "+tname)
			default:
				t.Errorf("Edge Relation has an unexpected type for %s", tname)
			}
		}
	}

	for name, e := range map[string]*dbt.Edge{
		"edge1": edge1,
		"edge2": edge2,
	} {
		err = suite.db.DeleteEdge(ctx, e.ID)
		assert.NoError(t, err, "Failed to delete "+name+" by ID")

		_, err = suite.db.FindEdgeById(ctx, e.ID)
		assert.Error(t, err, "Expected error when finding "+name+" removed by deletion")
	}
}

func (suite *PostgresEdgeTestSuite) TestOutgoingEdges() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before1 := time.Now()
	time.Sleep(100 * time.Millisecond)
	fqdn1, err := suite.db.CreateAsset(ctx, &oamdns.FQDN{Name: "owasp.org"})
	assert.NoError(t, err, "Failed to create asset for the FQDN")
	assert.NotNil(t, fqdn1, "Entity for the FQDN should not be nil")

	fqdn2, err := suite.db.CreateAsset(ctx, &oamdns.FQDN{Name: "www.owasp.org"})
	assert.NoError(t, err, "Failed to create asset for the FQDN")
	assert.NotNil(t, fqdn2, "Entity for the FQDN should not be nil")

	rel1 := &oamdns.BasicDNSRelation{
		Name: "dns_record",
		Header: oamdns.RRHeader{
			RRType: 5,
			Class:  1,
			TTL:    3200,
		},
	}
	edge1, err := suite.db.CreateEdge(ctx, &dbt.Edge{
		Relation:   rel1,
		FromEntity: fqdn1,
		ToEntity:   fqdn2,
	})
	assert.NoError(t, err, "Failed to create edge for the simple relation")
	assert.NotNil(t, edge1, "Edge should not be nil")
	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()

	time.Sleep(2 * time.Second)
	before2 := time.Now()
	time.Sleep(100 * time.Millisecond)

	rel2 := &oamgen.SimpleRelation{Name: "node"}
	edge2, err := suite.db.CreateEdge(ctx, &dbt.Edge{
		Relation:   rel2,
		FromEntity: fqdn1,
		ToEntity:   fqdn2,
	})
	assert.NoError(t, err, "Failed to create edge for the simple relation")
	assert.NotNil(t, edge2, "Edge should not be nil")
	time.Sleep(100 * time.Millisecond)
	after2 := time.Now()

	tests := map[string]struct {
		entity *dbt.Entity
		before time.Time
		after  time.Time
		since  time.Time
		labels []string
		count  int
	}{
		"fqdn1": {
			entity: fqdn1,
			before: before1,
			after:  after2,
			since:  time.Time{},
			labels: []string{"dns_record", "node"},
			count:  2,
		},
		"fqdn1 since before1": {
			entity: fqdn1,
			before: before1,
			after:  after2,
			since:  before1,
			labels: nil,
			count:  2,
		},
		"fqdn1 since before2": {
			entity: fqdn1,
			before: before2,
			after:  after2,
			since:  before2,
			count:  1,
		},
		"fqdn1 since after2": {
			entity: fqdn1,
			before: before1,
			after:  after1,
			since:  after2,
			count:  0,
		},
		"fqdn1 with label dns_record": {
			entity: fqdn1,
			before: before1,
			after:  after1,
			since:  time.Time{},
			labels: []string{"dns_record"},
			count:  1,
		},
		"fqdn1 with label node": {
			entity: fqdn1,
			before: before2,
			after:  after2,
			since:  time.Time{},
			labels: []string{"node"},
			count:  1,
		},
	}

	for tname, test := range tests {
		edges, err := suite.db.OutgoingEdges(ctx, test.entity, test.since, test.labels...)
		if test.count == 0 {
			assert.Error(t, err, "Expected error for "+tname)
			continue
		} else {
			assert.NoError(t, err, "Failed to get outgoing edges for "+tname)
			assert.Len(t, edges, test.count, "Unexpected number of outgoing edges for "+tname)
		}

		for _, edge := range edges {
			id, err := strconv.ParseInt(edge.ID, 10, 64)
			assert.NoError(t, err, "Edge ID is not a valid integer")
			assert.Greater(t, id, int64(0), "Edge ID is not greater than zero")
			assert.Equal(t, test.entity.ID, edge.FromEntity.ID, "Edge FromEntity ID does not match for "+tname)
			assert.Equal(t, fqdn2.ID, edge.ToEntity.ID, "Edge ToEntity ID does not match for "+tname)
			assert.WithinRange(t, edge.CreatedAt, test.before, test.after, "Edge CreateAt does not fall within range for "+tname)
			assert.WithinRange(t, edge.LastSeen, test.before, test.after, "Edge LastSeen does not fall within range for "+tname)

			switch rel := edge.Relation.(type) {
			case *oamdns.BasicDNSRelation:
				assert.Equal(t, rel1.Label(), rel.Label(), "Edge/Relation does not have a matching label for "+tname)
				assert.Equal(t, rel.Header.RRType, rel1.Header.RRType, "Edge/Relation found by ID does not have a matching Header.RRType")
				assert.Equal(t, rel.Header.Class, rel1.Header.Class, "Edge/Relation found by ID does not have a matching Header.Class")
				assert.Equal(t, rel.Header.TTL, rel1.Header.TTL, "Edge/Relation found by ID does not have a matching Header.TTL")
			case *oamgen.SimpleRelation:
				assert.Equal(t, rel2.Label(), rel.Label(), "Edge/Relation does not have a matching label for "+tname)
			default:
				t.Errorf("Edge Relation has an unexpected type for %s", tname)
			}
		}
	}

	for name, e := range map[string]*dbt.Edge{
		"edge1": edge1,
		"edge2": edge2,
	} {
		err = suite.db.DeleteEdge(ctx, e.ID)
		assert.NoError(t, err, "Failed to delete "+name+" by ID")

		_, err = suite.db.FindEdgeById(ctx, e.ID)
		assert.Error(t, err, "Expected error when finding "+name+" removed by deletion")
	}
}
