// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	_ "modernc.org/sqlite"
)

// Params: :unique_id, :bucket_name, :provider, :service, :bucket_exists, :is_public
//
// bucket_exists and is_public take the latest observation; provider and
// service keep a known value when a sighting leaves them out.
const upsertStorageBucketText = `
INSERT INTO storagebucket(unique_id, bucket_name, provider, service, bucket_exists, is_public)
VALUES (:unique_id, :bucket_name, :provider, :service, :bucket_exists, :is_public)
ON CONFLICT(unique_id) DO UPDATE SET
    bucket_name   = excluded.bucket_name,
    provider      = COALESCE(excluded.provider, storagebucket.provider),
    service       = COALESCE(excluded.service,  storagebucket.service),
    bucket_exists = excluded.bucket_exists,
    is_public     = excluded.is_public,
    updated_at    = CURRENT_TIMESTAMP`

// Param: :unique_id
const selectEntityIDByStorageBucketText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'storagebucket' LIMIT 1)
  AND natural_key = :unique_id
LIMIT 1`

// Param: :row_id
const selectStorageBucketByIDText = `
SELECT id, created_at, updated_at, unique_id, bucket_name, provider, service, bucket_exists, is_public
FROM storagebucket
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertStorageBucket(ctx context.Context, a *oamplat.StorageBucket) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid storage bucket provided")
	}
	if a.ID == "" {
		return 0, fmt.Errorf("the storage bucket does not have a unique identifier")
	}
	if a.Name == "" {
		return 0, fmt.Errorf("the storage bucket %s does not have a name", a.ID)
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.storagebucket.upsert",
		SQLText: upsertStorageBucketText,
		Args: []any{
			sql.Named("unique_id", a.ID),
			sql.Named("bucket_name", a.Name),
			sql.Named("provider", emptyToNil(a.Provider)),
			sql.Named("service", emptyToNil(a.Service)),
			sql.Named("bucket_exists", a.Exists),
			sql.Named("is_public", a.Public),
		},
		Result: done,
	})
	if err := <-done; err != nil {
		return 0, err
	}

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.storagebucket.entity_id_by_unique_id",
		SQLText: selectEntityIDByStorageBucketText,
		Args:    []any{sql.Named("unique_id", a.ID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return 0, result.Err
	}

	var id int64
	if err := result.Row.Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *SqliteRepository) fetchStorageBucketByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.storagebucket.by_id",
		SQLText: selectStorageBucketByIDText,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var c, u string
	var provider, service sql.NullString
	var a oamplat.StorageBucket
	if err := result.Row.Scan(&row_id, &c, &u, &a.ID, &a.Name,
		&provider, &service, &a.Exists, &a.Public); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, fmt.Errorf("no storage bucket record found with row ID %d", rowID)
	}
	if a.ID == "" {
		return nil, fmt.Errorf("storage bucket record with row ID %d is missing its unique ID", rowID)
	}
	a.Provider = provider.String
	a.Service = service.String

	e := &types.Entity{ID: strconv.FormatInt(eid, 10), Asset: &a}
	if created, err := parseTimestamp(c); err != nil {
		return nil, err
	} else {
		e.CreatedAt = created.In(time.UTC).Local()
	}
	if updated, err := parseTimestamp(u); err != nil {
		return nil, err
	} else {
		e.LastSeen = updated.In(time.UTC).Local()
	}

	return e, nil
}

// emptyToNil stores an empty optional value as NULL, so the upsert keeps a
// value already known.
func emptyToNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}
