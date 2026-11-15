// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"net/netip"
	"testing"

	"github.com/owasp-amass/asset-db/internal/iprange"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/stretchr/testify/assert"
)

func TestRangeQueries(t *testing.T) {
	query, params := addressesInRangeQuery(netip.MustParsePrefix("192.0.2.0/24"), 11)
	assert.Contains(t, query, "a.ip_key >= $first AND a.ip_key <= $last", "addresses are found by their keys")
	assert.Equal(t, iprange.Hex(iprange.Key(netip.MustParseAddr("192.0.2.0"))), params["first"], "the first key")
	assert.Equal(t, iprange.Hex(iprange.Key(netip.MustParseAddr("192.0.2.255"))), params["last"], "the last key")
	assert.Equal(t, 11, params["limit"], "the limit is a parameter")

	query, params = netblocksContainingQuery(netip.MustParseAddr("192.0.2.7"), 5)
	assert.Contains(t, query, "ORDER BY a.first_key DESC, a.last_key", "the most specific netblock comes first")
	assert.Equal(t, iprange.Hex(iprange.Key(netip.MustParseAddr("192.0.2.7"))), params["key"], "the address key")
}

func TestRangeKeysAreStored(t *testing.T) {
	m, err := entityPropsMap(entityOf(&oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.7"), Type: "IPv4"}))
	if assert.NoError(t, err, "an address's properties") {
		assert.Equal(t, iprange.Hex(iprange.Key(netip.MustParseAddr("192.0.2.7"))), m["ip_key"],
			"an address node carries its key")
	}

	m, err = entityPropsMap(entityOf(&oamnet.Netblock{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Type: "IPv4"}))
	if assert.NoError(t, err, "a netblock's properties") {
		assert.NotEmpty(t, m["first_key"], "a netblock node carries its first key")
		assert.NotEmpty(t, m["last_key"], "a netblock node carries its last key")
	}
}

func entityOf(a oam.Asset) *types.Entity {
	return &types.Entity{ID: "1", Asset: a}
}
