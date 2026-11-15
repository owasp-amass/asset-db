// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"net/netip"

	"github.com/owasp-amass/asset-db/repository/neo4j"
	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	"github.com/owasp-amass/asset-db/types"
)

// IPRangeReader is implemented by repositories that can search stored
// addresses and netblocks by range, whatever edges connect them.
type IPRangeReader interface {
	// FindAddressesInRange returns the IPAddress entities within prefix in
	// address order, at most limit (1..1000); more reports others.
	FindAddressesInRange(ctx context.Context, prefix netip.Prefix, limit int) ([]*types.Entity, bool, error)
	// FindNetblocksContaining returns the Netblock entities whose range
	// holds addr, the most specific first, at most limit (1..1000).
	FindNetblocksContaining(ctx context.Context, addr netip.Addr, limit int) ([]*types.Entity, error)
}

var (
	_ IPRangeReader = (*postgres.PostgresRepository)(nil)
	_ IPRangeReader = (*sqlite3.SqliteRepository)(nil)
	_ IPRangeReader = (*neo4j.NeoRepository)(nil)
)
