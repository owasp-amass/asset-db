// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"

	"github.com/owasp-amass/asset-db/internal/iprange"
	"github.com/owasp-amass/asset-db/types"
)

// FindAddressesInRange implements repository.IPRangeReader.
func (r *SqliteRepository) FindAddressesInRange(ctx context.Context, prefix netip.Prefix, limit int) ([]*types.Entity, bool, error) {
	if err := iprange.Check(prefix, limit); err != nil {
		return nil, false, err
	}

	first, last := iprange.Range(prefix)
	query := `SELECT e.entity_id FROM ipaddress a
        JOIN entity e ON e.table_name = 'ipaddress' AND e.row_id = a.id
        WHERE a.ip_key BETWEEN :first AND :last ORDER BY a.ip_key LIMIT :limit`
	return r.entitiesByID(ctx, query, []any{sql.Named("first", first), sql.Named("last", last),
		sql.Named("limit", limit+1)}, limit)
}

// FindNetblocksContaining implements repository.IPRangeReader.
func (r *SqliteRepository) FindNetblocksContaining(ctx context.Context, addr netip.Addr, limit int) ([]*types.Entity, error) {
	if !addr.IsValid() {
		return nil, errors.New("a valid address is required")
	}
	if err := iprange.Check(netip.PrefixFrom(addr, addr.BitLen()), limit); err != nil {
		return nil, err
	}

	// of the netblocks holding the address, a later first key is a smaller one
	key := iprange.Key(addr)
	query := `SELECT e.entity_id FROM netblock n
        JOIN entity e ON e.table_name = 'netblock' AND e.row_id = n.id
        WHERE n.first_key <= :key AND n.last_key >= :key
        ORDER BY n.first_key DESC, n.last_key ASC LIMIT :limit`
	out, _, err := r.entitiesByID(ctx, query, []any{sql.Named("key", key), sql.Named("limit", limit)}, limit)
	return out, err
}

// fillRangeKeys writes the range keys of addresses and netblocks stored
// without them: before migration 006, or by another tool.
func (r *SqliteRepository) fillRangeKeys() error {
	type row struct {
		id   int64
		text string
	}
	read := func(query string) ([]row, error) {
		rows, err := r.DB.Query(query)
		if err != nil {
			return nil, err
		}

		defer func() { _ = rows.Close() }()

		var out []row
		for rows.Next() {
			var x row
			if err := rows.Scan(&x.id, &x.text); err != nil {
				return nil, err
			}

			out = append(out, x)
		}

		return out, rows.Err()
	}

	addrs, err := read(`SELECT id, ip_address FROM ipaddress WHERE ip_key IS NULL`)
	if err != nil {
		return err
	}

	nets, err := read(`SELECT id, netblock_cidr FROM netblock WHERE first_key IS NULL OR last_key IS NULL`)
	if err != nil {
		return err
	}
	if len(addrs) == 0 && len(nets) == 0 {
		return nil
	}

	tx, err := r.DB.Begin()
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if addr, err := netip.ParseAddr(a.text); err == nil {
			if _, err := tx.Exec(`UPDATE ipaddress SET ip_key = ? WHERE id = ?`, iprange.Key(addr), a.id); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
	}
	for _, n := range nets {
		if p, err := netip.ParsePrefix(n.text); err == nil {
			first, last := iprange.Range(p)
			if _, err := tx.Exec(`UPDATE netblock SET first_key = ?, last_key = ? WHERE id = ?`, first, last,
				n.id); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
	}

	return tx.Commit()
}
