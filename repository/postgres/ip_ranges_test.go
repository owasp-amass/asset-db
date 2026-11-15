// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"net/netip"
	"testing"

	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Stored addresses and netblocks are found by range, with no edge between
// them.
func TestPostgresIPRanges(t *testing.T) {
	db := valueFinderRepo(t)
	ctx := context.Background()

	for _, a := range []string{"192.0.2.200", "192.0.2.7", "192.0.3.1", "2001:db8::5"} {
		addr := netip.MustParseAddr(a)
		typ := "IPv4"
		if addr.Is6() {
			typ = "IPv6"
		}

		_, err := db.CreateAsset(ctx, &oamnet.IPAddress{Address: addr, Type: typ})
		require.NoError(t, err, "storing %s", a)
	}
	for _, c := range []string{"192.0.0.0/16", "192.0.2.0/24", "198.51.100.0/24"} {
		_, err := db.CreateAsset(ctx, &oamnet.Netblock{CIDR: netip.MustParsePrefix(c), Type: "IPv4"})
		require.NoError(t, err, "storing %s", c)
	}

	keys := func(ents []string) []string { return ents }
	found, more, err := db.FindAddressesInRange(ctx, netip.MustParsePrefix("192.0.2.0/24"), 10)
	require.NoError(t, err, "finding the addresses in a /24")
	var got []string
	for _, e := range found {
		got = append(got, e.Asset.Key())
	}

	assert.Equal(t, keys([]string{"192.0.2.7", "192.0.2.200"}), got, "the /24's addresses in address order")
	assert.False(t, more, "no more addresses in the /24")

	found, more, err = db.FindAddressesInRange(ctx, netip.MustParsePrefix("192.0.0.0/16"), 2)
	require.NoError(t, err, "finding the addresses in a /16")
	assert.Len(t, found, 2, "the limit is kept")
	assert.True(t, more, "a third address in the /16 is reported")

	found, _, err = db.FindAddressesInRange(ctx, netip.MustParsePrefix("2001:db8::/32"), 10)
	require.NoError(t, err, "finding IPv6 addresses")
	assert.Len(t, found, 1, "the IPv6 address is found, not the IPv4 ones")

	nets, err := db.FindNetblocksContaining(ctx, netip.MustParseAddr("192.0.2.7"), 10)
	require.NoError(t, err, "finding the netblocks holding an address")
	got = nil
	for _, e := range nets {
		got = append(got, e.Asset.Key())
	}

	assert.Equal(t, []string{"192.0.2.0/24", "192.0.0.0/16"}, got, "the most specific netblock comes first")

	nets, err = db.FindNetblocksContaining(ctx, netip.MustParseAddr("203.0.113.1"), 10)
	assert.NoError(t, err, "an address no netblock holds")
	assert.Empty(t, nets, "no netblock holds it")

	_, _, err = db.FindAddressesInRange(ctx, netip.Prefix{}, 10)
	assert.Error(t, err, "an invalid prefix is refused")
}
