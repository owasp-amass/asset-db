// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// maxCachedEntityTypes bounds the entity type cache, which is emptied when
// full: at about 20 bytes an entry it stays near 5 MB, so a repository on a
// small machine, or each of many sessions, pays little for it.
const maxCachedEntityTypes = 1 << 18

// entityTypes remembers the asset type of each entity ID the repository has
// read or written. An entity's type never changes and IDs are not reused,
// so reading an entity whose type is known takes one query instead of two,
// and storing an edge needs no reads to check the relationship. A cached
// entity that was deleted reads as not found, as before. Types are kept as
// small indexes into typeNames.
type entityTypes struct {
	mu sync.RWMutex
	m  map[int64]uint8
}

// typeNames are the lowercase type names the database stores, in the
// order of oam.AssetList; typeIndex maps each back to its index.
var typeNames, typeIndex = func() ([]string, map[string]uint8) {
	names := make([]string, 0, len(oam.AssetList))
	index := make(map[string]uint8, len(oam.AssetList))
	for i, t := range oam.AssetList {
		n := normalizeType(string(t))
		names = append(names, n)
		index[n] = uint8(i)
	}

	return names, index
}()

func newEntityTypes() *entityTypes { return &entityTypes{m: make(map[int64]uint8)} }

func (c *entityTypes) get(eid int64) (string, bool) {
	if c == nil {
		return "", false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	i, ok := c.m[eid]
	if !ok {
		return "", false
	}

	return typeNames[i], true
}

func (c *entityTypes) put(eid int64, etype string) {
	i, known := typeIndex[etype]
	if c == nil || !known {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.m) >= maxCachedEntityTypes {
		c.m = make(map[int64]uint8)
	}

	c.m[eid] = i
}

func (c *entityTypes) forget(eid int64) {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.m, eid)
}

// remember records the types of entities read from the database.
func (r *PostgresRepository) remember(ents ...*dbt.Entity) {
	for _, e := range ents {
		if e == nil || e.Asset == nil {
			continue
		}
		if eid, err := strconv.ParseInt(e.ID, 10, 64); err == nil {
			r.types.put(eid, normalizeType(string(e.Asset.AssetType())))
		}
	}
}

// fetchEntityOfType reads one entity whose asset type is known, in one query.
func (r *PostgresRepository) fetchEntityOfType(ctx context.Context, eid int64, etype string) (*dbt.Entity, error) {
	reader, ok := entitiesByIdsReaders[etype]
	if !ok {
		return nil, fmt.Errorf("unhandled entity type %q", etype)
	}

	ents, err := reader.scan(r, ctx, reader.query, pgx.NamedArgs{"ids": []int64{eid}})
	if err != nil {
		return nil, err
	}
	if len(ents) == 0 {
		r.types.forget(eid)
		return nil, pgx.ErrNoRows
	}

	return ents[0], nil
}

// entityTypesOf returns the asset types of the entity IDs, from the cache
// or, for the others, from one query. An ID with no entity is left out.
func (r *PostgresRepository) entityTypesOf(ctx context.Context, eids ...int64) (map[int64]string, error) {
	out := make(map[int64]string, len(eids))

	var missing []int64
	for _, eid := range eids {
		if t, ok := r.types.get(eid); ok {
			out[eid] = t
		} else {
			missing = append(missing, eid)
		}
	}
	if len(missing) == 0 {
		return out, nil
	}

	j := NewRowsJob(ctx, selectEntityTypesByIdsText, pgx.NamedArgs{"ids": missing}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid int64
			var etype string
			if err := rows.Scan(&eid, &etype); err != nil {
				return err
			}

			etype = strings.ToLower(etype)
			out[eid] = etype
			r.types.put(eid, etype)
		}

		return rows.Err()
	})

	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	return out, nil
}

// assetTypes maps the lowercase type names the database stores to OAM asset types.
var assetTypes = func() map[string]oam.AssetType {
	m := make(map[string]oam.AssetType, len(oam.AssetList))
	for _, t := range oam.AssetList {
		m[normalizeType(string(t))] = t
	}

	return m
}()

// errEntityTypeUnknown explains an entity with no stored or known type.
func errEntityTypeUnknown(etype string) error {
	if etype == "" {
		return pgx.ErrNoRows
	}

	return fmt.Errorf("unknown entity type %q", etype)
}
