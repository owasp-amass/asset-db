// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"
	"errors"
	"net/netip"
	"time"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/owasp-amass/asset-db/internal/iprange"
	"github.com/owasp-amass/asset-db/types"
)

// Address and netblock nodes carry hexadecimal range keys (ip_key, and
// first_key and last_key) that sort as the addresses do.

// FindAddressesInRange implements repository.IPRangeReader.
func (neo *NeoRepository) FindAddressesInRange(ctx context.Context, prefix netip.Prefix, limit int) ([]*types.Entity, bool, error) {
	if err := iprange.Check(prefix, limit); err != nil {
		return nil, false, err
	}

	query, params := addressesInRangeQuery(prefix, limit+1)
	ents, err := neo.entityQuery(ctx, query, params)
	if err != nil {
		return nil, false, err
	}

	more := len(ents) > limit
	if more {
		ents = ents[:limit]
	}

	return ents, more, nil
}

// FindNetblocksContaining implements repository.IPRangeReader.
func (neo *NeoRepository) FindNetblocksContaining(ctx context.Context, addr netip.Addr, limit int) ([]*types.Entity, error) {
	if !addr.IsValid() {
		return nil, errors.New("a valid address is required")
	}
	if err := iprange.Check(netip.PrefixFrom(addr, addr.BitLen()), limit); err != nil {
		return nil, err
	}

	query, params := netblocksContainingQuery(addr, limit)
	return neo.entityQuery(ctx, query, params)
}

func addressesInRangeQuery(prefix netip.Prefix, limit int) (string, map[string]any) {
	first, last := iprange.Range(prefix)
	return "MATCH (a:Entity:IPAddress) WHERE a.ip_key >= $first AND a.ip_key <= $last RETURN a " +
			"ORDER BY a.ip_key LIMIT $limit",
		map[string]any{"first": iprange.Hex(first), "last": iprange.Hex(last), "limit": limit}
}

// netblocksContainingQuery orders the netblocks holding the address with a
// later first key, a smaller netblock, first.
func netblocksContainingQuery(addr netip.Addr, limit int) (string, map[string]any) {
	return "MATCH (a:Entity:Netblock) WHERE a.first_key <= $key AND a.last_key >= $key RETURN a " +
			"ORDER BY a.first_key DESC, a.last_key LIMIT $limit",
		map[string]any{"key": iprange.Hex(iprange.Key(addr)), "limit": limit}
}

func (neo *NeoRepository) entityQuery(ctx context.Context, query string, params map[string]any) ([]*types.Entity, error) {
	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(tctx, neo.DB, query, params, neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname))
	if err != nil {
		return nil, err
	}

	var out []*types.Entity
	for _, rec := range result.Records {
		node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](rec, "a")
		if err != nil || isnil {
			continue
		}
		if ent, err := nodeToEntity(node); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

// fillRangeKeys sets the range keys of address and netblock nodes stored
// without them: before asset-db wrote them, or by another tool. A value that
// does not parse gets an empty key, so it is not read again.
func (neo *NeoRepository) fillRangeKeys(ctx context.Context) error {
	for _, step := range []struct {
		find string
		set  string
		keys func(string) (map[string]any, bool)
	}{
		{
			find: "MATCH (a:Entity:IPAddress) WHERE a.ip_key IS NULL AND a.address IS NOT NULL " +
				"RETURN elementId(a) AS id, a.address AS v LIMIT 1000",
			set: "UNWIND $rows AS row MATCH (a) WHERE elementId(a) = row.id SET a.ip_key = row.ip_key",
			keys: func(v string) (map[string]any, bool) {
				addr, err := netip.ParseAddr(v)
				if err != nil {
					// an empty key marks the node done; it matches no range
					return map[string]any{"ip_key": ""}, true
				}

				return map[string]any{"ip_key": iprange.Hex(iprange.Key(addr))}, true
			},
		},
		{
			find: "MATCH (a:Entity:Netblock) WHERE a.first_key IS NULL AND a.cidr IS NOT NULL " +
				"RETURN elementId(a) AS id, a.cidr AS v LIMIT 1000",
			set: "UNWIND $rows AS row MATCH (a) WHERE elementId(a) = row.id " +
				"SET a.first_key = row.first_key, a.last_key = row.last_key",
			keys: func(v string) (map[string]any, bool) {
				p, err := netip.ParsePrefix(v)
				if err != nil {
					return map[string]any{"first_key": "", "last_key": ""}, true
				}

				first, last := iprange.Range(p)
				return map[string]any{"first_key": iprange.Hex(first), "last_key": iprange.Hex(last)}, true
			},
		},
	} {
		for {
			result, err := neo4jdb.ExecuteQuery(ctx, neo.DB, step.find, nil, neo4jdb.EagerResultTransformer,
				neo4jdb.ExecuteQueryWithDatabase(neo.dbname))
			if err != nil {
				return err
			}

			var rows []map[string]any
			for _, rec := range result.Records {
				id, _, _ := neo4jdb.GetRecordValue[string](rec, "id")
				v, _, _ := neo4jdb.GetRecordValue[string](rec, "v")
				if keys, ok := step.keys(v); ok {
					keys["id"] = id
					rows = append(rows, keys)
				}
			}
			if len(rows) == 0 {
				break
			}
			if _, err := neo4jdb.ExecuteQuery(ctx, neo.DB, step.set, map[string]any{"rows": rows},
				neo4jdb.EagerResultTransformer, neo4jdb.ExecuteQueryWithDatabase(neo.dbname)); err != nil {
				return err
			}
			if len(result.Records) < 1000 {
				break
			}
		}
	}

	return nil
}
