// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"net/netip"
	"path/filepath"
	"testing"

	sqlitemigrations "github.com/owasp-amass/asset-db/migrations/sqlite3"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	migrate "github.com/rubenv/sql-migrate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Stored addresses and netblocks are found by range, with no edge between
// them.
func TestSQLiteIPRanges(t *testing.T) {
	db, dir, err := setupTempSQLite()
	require.NoError(t, err, "creating the database")
	defer teardownTempSQLite(db, dir)
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

// Addresses and netblocks stored without range keys, before migration 006
// or by another tool, get them when the database is opened.
func TestSQLiteRangeKeysFilledOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.db")
	raw, err := sql.Open("sqlite", path)
	require.NoError(t, err, "opening the file")
	src := migrate.EmbedFileSystemMigrationSource{FileSystem: sqlitemigrations.Migrations(), Root: "/"}
	_, err = migrate.ExecMax(raw, "sqlite3", src, migrate.Up, 5)
	require.NoError(t, err, "migrating to 005")
	_, err = raw.Exec(`INSERT INTO ipaddress(ip_address, attrs) VALUES ('192.0.2.9', '{"type":"IPv4"}')`)
	require.NoError(t, err, "storing an address without a key")
	_, err = raw.Exec(`INSERT INTO netblock(netblock_cidr, attrs) VALUES ('192.0.2.0/24', '{"type":"IPv4"}')`)
	require.NoError(t, err, "storing a netblock without keys")
	require.NoError(t, raw.Close(), "closing the file")

	db, err := New(SQLite, path)
	require.NoError(t, err, "opening the repository")
	defer func() { _ = db.Close() }()

	found, _, err := db.FindAddressesInRange(context.Background(), netip.MustParsePrefix("192.0.2.0/24"), 5)
	require.NoError(t, err, "finding the address by range")
	assert.Len(t, found, 1, "the address stored without a key is found")
	nets, err := db.FindNetblocksContaining(context.Background(), netip.MustParseAddr("192.0.2.9"), 5)
	require.NoError(t, err, "finding the netblock by address")
	assert.Len(t, nets, 1, "the netblock stored without keys is found")
}
