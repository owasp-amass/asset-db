// Copyright © by Jeff Foley 2017-2026. All rights reserved.
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

	"github.com/caffix/stringset"
	"github.com/owasp-amass/asset-db/repository/postgres/testhelpers"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PostgresEntityTestSuite struct {
	suite.Suite
	container *testhelpers.PostgresContainer
	db        *PostgresRepository
}

func TestPostgresEntityTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresEntityTestSuite))
}

func (suite *PostgresEntityTestSuite) SetupSuite() {
	var err error
	suite.container, suite.db, err = setupContainerAndPostgresRepo()
	if err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresEntityTestSuite) TearDownSuite() {
	if err := suite.container.Terminate(context.Background()); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func (suite *PostgresEntityTestSuite) TestFindEntitiesByType() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before1 := time.Now()
	time.Sleep(100 * time.Millisecond)
	set1 := stringset.New("example.com", "test.com", "sample.org")
	for _, name := range set1.Slice() {
		fqdn, err := suite.db.CreateAsset(ctx, &oamdns.FQDN{Name: name})
		assert.NoError(t, err, "Failed to create FQDN '%s'", name)
		assert.NotNil(t, fqdn, "Entity for the FQDN '%s' should not be nil", name)
	}
	ip1, err := suite.db.CreateAsset(ctx, &oamnet.IPAddress{
		Address: netip.MustParseAddr("104.20.44.163"),
		Type:    "IPv4",
	})
	assert.NoError(t, err, "Failed to create asset for the IPAddress")
	assert.NotNil(t, ip1, "Entity for the IPAddress should not be nil")
	ip1set := stringset.New("104.20.44.163")
	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()

	time.Sleep(1 * time.Second)

	before2 := time.Now()
	time.Sleep(100 * time.Millisecond)
	set2 := stringset.New("example.net", "demo.com", "website.org")
	for _, name := range set2.Slice() {
		fqdn, err := suite.db.CreateAsset(ctx, &oamdns.FQDN{Name: name})
		assert.NoError(t, err, "Failed to create FQDN '%s'", name)
		assert.NotNil(t, fqdn, "Entity for the FQDN '%s' should not be nil", name)
	}
	ip2, err := suite.db.CreateAsset(ctx, &oamnet.IPAddress{
		Address: netip.MustParseAddr("172.66.157.115"),
		Type:    "IPv4",
	})
	assert.NoError(t, err, "Failed to create asset for the IPAddress")
	assert.NotNil(t, ip2, "Entity for the IPAddress should not be nil")
	ip2set := stringset.New("172.66.157.115")
	time.Sleep(100 * time.Millisecond)
	after2 := time.Now()

	tests := map[string]struct {
		atype  oam.AssetType
		before time.Time
		after  time.Time
		since  time.Time
		sets   []*stringset.Set
		count  int
	}{
		"all fqdns": {
			atype:  oam.FQDN,
			before: before1,
			after:  after2,
			since:  before1,
			sets:   []*stringset.Set{set1, set2},
			count:  6,
		},
		"ips since before1": {
			atype:  oam.IPAddress,
			before: before1,
			after:  after2,
			since:  before1,
			sets:   []*stringset.Set{ip1set, ip2set},
			count:  2,
		},
		"fqdns since before2": {
			atype:  oam.FQDN,
			before: before2,
			after:  after2,
			since:  before2,
			sets:   []*stringset.Set{set2},
			count:  3,
		},
		"fqdns since after2": {
			atype:  oam.FQDN,
			before: before1,
			after:  after1,
			since:  after2,
			sets:   []*stringset.Set{},
			count:  0,
		},
		"ips since before2": {
			atype:  oam.IPAddress,
			before: before2,
			after:  after2,
			since:  before2,
			sets:   []*stringset.Set{ip2set},
			count:  1,
		},
		"ips since after2": {
			atype:  oam.IPAddress,
			before: before2,
			after:  after2,
			since:  after2,
			sets:   []*stringset.Set{},
			count:  0,
		},
	}

	for tname, test := range tests {
		entities, err := suite.db.FindEntitiesByType(ctx, test.atype, test.since, 0)
		if test.count == 0 {
			assert.Error(t, err, "Expected error for "+tname)
			continue
		} else {
			assert.NoError(t, err, "Failed to get entities for "+tname)
			assert.Len(t, entities, test.count, "Unexpected number of entities for "+tname)
		}

		for _, entity := range entities {
			id, err := strconv.ParseInt(entity.ID, 10, 64)
			assert.NoError(t, err, "Entity ID is not a valid integer")
			assert.Greater(t, id, int64(0), "Entity ID is not greater than zero")
			assert.WithinRange(t, entity.CreatedAt, test.before, test.after, "Entity CreatedAt does not fall within range for "+tname)
			assert.WithinRange(t, entity.LastSeen, test.before, test.after, "Entity LastSeen does not fall within range for "+tname)

			switch a := entity.Asset.(type) {
			case *oamdns.FQDN:
				var found bool
				for _, s := range test.sets {
					if s.Has(a.Name) {
						found = true
						break
					}
				}
				if !found {
					assert.Fail(t, "FQDN not found in expected set for "+tname, a.Name)
				}
			case *oamnet.IPAddress:
				var found bool
				for _, s := range test.sets {
					if s.Has(a.Address.String()) {
						found = true
						break
					}
				}
				if !found {
					assert.Fail(t, "IP address not found in expected set for "+tname, a.Address.String())
				}
			default:
				t.Errorf("Entity Asset has an unexpected type for %s", tname)
			}
		}
	}
}
