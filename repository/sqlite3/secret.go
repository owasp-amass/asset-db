// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/owasp-amass/asset-db/types"
)

const secretColumns = `name, ciphertext, nonce, key_id, updated_at, updated_by`

// PutSecret implements repository.SecretStore.
func (r *SqliteRepository) PutSecret(ctx context.Context, s *types.Secret) (*types.Secret, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}

	out := *s
	out.UpdatedAt = time.Now().UTC().Truncate(time.Millisecond)
	err := r.write(ctx, "secret.put", `INSERT INTO secret (name, ciphertext, nonce, key_id, updated_at, updated_by)
        VALUES (:name, :ciphertext, :nonce, :key_id, :updated, :by)
        ON CONFLICT (name) DO UPDATE SET ciphertext = excluded.ciphertext, nonce = excluded.nonce,
          key_id = excluded.key_id, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
		sql.Named("name", s.Name), sql.Named("ciphertext", s.Ciphertext), sql.Named("nonce", s.Nonce),
		sql.Named("key_id", s.KeyID), sql.Named("updated", out.UpdatedAt.Format(runTimeLayout)),
		sql.Named("by", s.UpdatedBy))
	if err != nil {
		return nil, err
	}
	out.UpdatedAt = out.UpdatedAt.Local()
	return &out, nil
}

// GetSecret implements repository.SecretStore.
func (r *SqliteRepository) GetSecret(ctx context.Context, name string) (*types.Secret, error) {
	all, err := r.querySecrets(ctx, "secret.get", `SELECT `+secretColumns+` FROM secret WHERE name = :name`,
		sql.Named("name", name))
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, errors.New("no secret has this name")
	}
	return all[0], nil
}

// ListSecrets implements repository.SecretStore.
func (r *SqliteRepository) ListSecrets(ctx context.Context) ([]*types.Secret, error) {
	return r.querySecrets(ctx, "secret.list", `SELECT `+secretColumns+` FROM secret ORDER BY name`)
}

// DeleteSecret implements repository.SecretStore.
func (r *SqliteRepository) DeleteSecret(ctx context.Context, name string) error {
	return r.write(ctx, "secret.delete", `DELETE FROM secret WHERE name = :name`, sql.Named("name", name))
}

func (r *SqliteRepository) querySecrets(ctx context.Context, name, query string, args ...any) ([]*types.Secret, error) {
	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{Ctx: ctx, Name: name, SQLText: query, Args: args, Result: ch})
	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}
	defer func() { _ = result.Rows.Close() }()

	var out []*types.Secret
	for result.Rows.Next() {
		var s types.Secret
		var updated string
		if err := result.Rows.Scan(&s.Name, &s.Ciphertext, &s.Nonce, &s.KeyID, &updated, &s.UpdatedBy); err != nil {
			return nil, err
		}
		t, err := parseTimestamp(updated)
		if err != nil {
			return nil, err
		}
		s.UpdatedAt = t.In(time.UTC).Local()
		out = append(out, &s)
	}
	return out, result.Rows.Err()
}
