// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package iprange

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeysSortAsAddresses(t *testing.T) {
	addrs := []string{
		"10.0.0.1",
		"10.0.0.255",
		"10.0.1.0",
		"192.0.2.7",
		"255.255.255.255",
		"2001:db8::1",
		"2001:db8::2",
	}
	for i := 1; i < len(addrs); i++ {
		a, b := Key(netip.MustParseAddr(addrs[i-1])), Key(netip.MustParseAddr(addrs[i]))
		assert.Equal(t, -1, bytes.Compare(a, b), "%s should sort before %s", addrs[i-1], addrs[i])
		assert.Less(t, Hex(a), Hex(b), "the hex of %s should sort before %s", addrs[i-1], addrs[i])
	}

	assert.Equal(t, Key(netip.MustParseAddr("192.0.2.7")), Key(netip.MustParseAddr("::ffff:192.0.2.7")),
		"an IPv4-mapped address has its IPv4 key")
}

func TestRange(t *testing.T) {
	first, last := Range(netip.MustParsePrefix("192.0.2.77/24"))
	assert.Equal(t, Key(netip.MustParseAddr("192.0.2.0")), first, "the range starts at the network address")
	assert.Equal(t, Key(netip.MustParseAddr("192.0.2.255")), last, "the range ends at the broadcast address")

	first, last = Range(netip.MustParsePrefix("2001:db8::/32"))
	assert.Equal(t, Key(netip.MustParseAddr("2001:db8::")), first, "an IPv6 range starts at its first address")
	assert.Equal(t, Key(netip.MustParseAddr("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")), last,
		"an IPv6 range ends at its last address")

	assert.Error(t, Check(netip.Prefix{}, 10), "an invalid prefix is refused")
	assert.Error(t, Check(netip.MustParsePrefix("10.0.0.0/8"), 0), "a zero limit is refused")
	assert.NoError(t, Check(netip.MustParsePrefix("10.0.0.0/8"), 10), "a prefix and limit are accepted")
}
