// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"
	"net/netip"

	"github.com/owasp-amass/asset-db/internal/iprange"
	"github.com/owasp-amass/asset-db/types"
)

// FindAddressesInRange implements repository.IPRangeReader.
func (r *PostgresRepository) FindAddressesInRange(ctx context.Context, prefix netip.Prefix, limit int) ([]*types.Entity, bool, error) {
	if err := iprange.Check(prefix, limit); err != nil {
		return nil, false, err
	}

	query := `SELECT e.entity_id FROM public.ipaddress a
        JOIN public.entity e ON e.table_name = 'public.ipaddress'::citext AND e.row_id = a.id
        WHERE a.ip_address <<= $1::cidr ORDER BY a.ip_address LIMIT $2`
	return r.entitiesByID(ctx, query, []any{prefix.Masked().String(), limit + 1}, limit)
}

// FindNetblocksContaining implements repository.IPRangeReader.
func (r *PostgresRepository) FindNetblocksContaining(ctx context.Context, addr netip.Addr, limit int) ([]*types.Entity, error) {
	if !addr.IsValid() {
		return nil, errors.New("a valid address is required")
	}
	if err := iprange.Check(netip.PrefixFrom(addr, addr.BitLen()), limit); err != nil {
		return nil, err
	}

	query := `SELECT e.entity_id FROM public.netblock n
        JOIN public.entity e ON e.table_name = 'public.netblock'::citext AND e.row_id = n.id
        WHERE n.netblock_cidr >>= $1::inet ORDER BY masklen(n.netblock_cidr) DESC, n.id LIMIT $2`
	out, _, err := r.entitiesByID(ctx, query, []any{addr.Unmap().String(), limit}, limit)
	return out, err
}
