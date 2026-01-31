// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"net/netip"
	"strconv"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/stretchr/testify/assert"
)

func TestCreateAssetForNetblock(t *testing.T) {
	db, dir, err := setupTempSQLite()
	assert.NoError(t, err, "Failed to create the sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer teardownTempSQLite(db, dir)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	cidr := netip.MustParsePrefix("72.237.4.0/24")
	iptype := "IPv4"
	netblock, err := db.CreateAsset(ctx, &oamnet.Netblock{
		CIDR: cidr,
		Type: iptype,
	})
	assert.NoError(t, err, "Failed to create asset for the Netblock")
	assert.NotNil(t, netblock, "Entity for the Netblock should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, netblock.CreatedAt, before, after, "Netblock entity CreatedAt is incorrect")
	assert.WithinRange(t, netblock.LastSeen, before, after, "Netblock entity LastSeen is incorrect")

	id, err := strconv.ParseInt(netblock.ID, 10, 64)
	assert.NoError(t, err, "Netblock entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "Netblock entity ID is not greater than zero")

	found, err := db.FindEntityById(ctx, netblock.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the Netblock")
	assert.NotNil(t, found, "Entity found by ID for the Netblock should not be nil")
	assert.Equal(t, netblock.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the Netblock does not match")
	assert.Equal(t, netblock.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the Netblock does not match")

	netblock2, ok := found.Asset.(*oamnet.Netblock)
	assert.True(t, ok, "Asset found by ID is not of type *oamnet.Netblock")
	assert.Equal(t, found.ID, netblock.ID, "Netblock found by Entity ID does not have matching IDs")
	assert.Equal(t, netblock2.CIDR, cidr, "Netblock found by ID does not have a matching CIDR")
	assert.Equal(t, netblock2.Type, iptype, "Netblock found by ID does not have a matching Type")

	err = db.DeleteEntity(ctx, netblock.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the Netblock")

	_, err = db.FindEntityById(ctx, netblock.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the Netblock")
}

func TestFindEntitiesByContentForNetblock(t *testing.T) {
	db, dir, err := setupTempSQLite()
	assert.NoError(t, err, "Failed to create the sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer teardownTempSQLite(db, dir)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	cidr := netip.MustParsePrefix("72.237.4.0/24")
	iptype := "IPv4"
	netblock, err := db.CreateAsset(ctx, &oamnet.Netblock{
		CIDR: cidr,
		Type: iptype,
	})
	assert.NoError(t, err, "Failed to create asset for the Netblock")
	assert.NotNil(t, netblock, "Entity for the Netblock should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	cidrstr := cidr.String()
	_, err = db.FindEntitiesByContent(ctx, oam.Netblock, after, 1, dbt.ContentFilters{
		"cidr": cidrstr,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	ents, err := db.FindEntitiesByContent(ctx, oam.Netblock, before, 1, dbt.ContentFilters{
		"cidr": cidrstr,
	})
	assert.NoError(t, err, "Failed to find entity by content for the Netblock")
	found := ents[0]
	assert.NotNil(t, found, "Entity found by content for the Netblock should not be nil")

	netblock2, ok := found.Asset.(*oamnet.Netblock)
	assert.True(t, ok, "Netblock found by content is not of type *oamnet.Netblock")
	assert.Equal(t, found.ID, netblock.ID, "Netblock found by content does not have matching IDs")
	assert.Equal(t, netblock2.CIDR, cidr, "Netblock found by ID does not have a matching CIDR")
	assert.Equal(t, netblock2.Type, iptype, "Netblock found by ID does not have a matching Type")

	ents, err = db.FindEntitiesByContent(ctx, oam.Netblock, before, 0, dbt.ContentFilters{
		"cidr": cidrstr,
	})
	assert.NoError(t, err, "Failed to find entities by content for the Netblock")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the Netblock")
}

func TestFindEntitiesByTypeForNetblock(t *testing.T) {
	db, dir, err := setupTempSQLite()
	assert.NoError(t, err, "Failed to create the sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer teardownTempSQLite(db, dir)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	since1 := time.Now()
	time.Sleep(100 * time.Millisecond)

	iptype := "IPv4"
	atype := oam.Netblock
	atypestr := "Netblock"
	cidr := netip.MustParsePrefix("72.237.4.0/24")
	key1 := cidr.String()
	ent, err := db.CreateAsset(ctx, &oamnet.Netblock{
		CIDR: cidr,
		Type: iptype,
	})
	assert.NoError(t, err, "Failed to create asset for the first %s", atypestr)
	assert.NotNil(t, ent, "Entity for the first %s should not be nil", atypestr)

	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()
	time.Sleep(500 * time.Millisecond)
	since23 := time.Now()
	time.Sleep(100 * time.Millisecond)

	cidr = netip.MustParsePrefix("150.156.0.0/16")
	key2 := cidr.String()
	ent, err = db.CreateAsset(ctx, &oamnet.Netblock{
		CIDR: cidr,
		Type: iptype,
	})
	assert.NoError(t, err, "Failed to create asset for the second %s", atypestr)
	assert.NotNil(t, ent, "Entity for the second %s should not be nil", atypestr)

	cidr = netip.MustParsePrefix("192.168.1.0/24")
	key3 := cidr.String()
	ent, err = db.CreateAsset(ctx, &oamnet.Netblock{
		CIDR: cidr,
		Type: iptype,
	})
	assert.NoError(t, err, "Failed to create asset for the third %s", atypestr)
	assert.NotNil(t, ent, "Entity for the third %s should not be nil", atypestr)

	time.Sleep(100 * time.Millisecond)
	after23 := time.Now()

	for k, v := range map[string]struct {
		since    time.Time
		limit    int
		expected []string
	}{
		"find all since1": {
			since:    since1,
			limit:    3,
			expected: []string{key3, key2, key1},
		},
		"one out of all": {
			since:    since1,
			limit:    1,
			expected: []string{key3},
		},
		"two out of all": {
			since:    since1,
			limit:    2,
			expected: []string{key3, key2},
		},
		"find all after1": {
			since:    after1,
			limit:    3,
			expected: []string{key3, key2},
		},
		"one out of two and three": {
			since:    since23,
			limit:    1,
			expected: []string{key3},
		},
		"zero entities after23": {
			since:    after23,
			limit:    3,
			expected: []string{},
		},
		"no since returns error": {
			since:    time.Time{},
			limit:    0,
			expected: []string{},
		},
	} {
		ents, err := db.FindEntitiesByType(ctx, atype, v.since, v.limit)

		var got []string
		for _, ent := range ents {
			got = append(got, ent.Asset.Key())
		}

		if len(v.expected) > 0 {
			assert.NoError(t, err, "The %s test failed for %s: expected %v: got: %v", k, atypestr, v.expected, got)
		} else {
			assert.Error(t, err, "The %s test failed for %s: zero findings should return an error", k, atypestr)
		}

		assert.Len(t, ents, len(v.expected),
			"The %s test expected to find exactly %d entities for %s: got: %d", k, v.limit, atypestr, len(ents),
		)
	}
}
