// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/owasp-amass/asset-db/types"
)

const secretColumns = `name, ciphertext, nonce, key_id, updated_at, updated_by`

// PutSecret implements repository.SecretStore.
func (r *PostgresRepository) PutSecret(ctx context.Context, s *types.Secret) (*types.Secret, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}

	out := *s
	j := NewRowJob(ctx, `INSERT INTO public.secret (name, ciphertext, nonce, key_id, updated_by)
        VALUES (@name, @ciphertext, @nonce, @key_id, @by)
        ON CONFLICT (name) DO UPDATE SET ciphertext = excluded.ciphertext, nonce = excluded.nonce,
          key_id = excluded.key_id, updated_at = timezone('utc', now()), updated_by = excluded.updated_by
        RETURNING updated_at`, pgx.NamedArgs{"name": s.Name, "ciphertext": s.Ciphertext, "nonce": s.Nonce,
		"key_id": s.KeyID, "by": s.UpdatedBy}, func(row pgx.Row) error { return row.Scan(&out.UpdatedAt) })
	r.wpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}
	out.UpdatedAt = out.UpdatedAt.In(time.UTC).Local()
	return &out, nil
}

// GetSecret implements repository.SecretStore.
func (r *PostgresRepository) GetSecret(ctx context.Context, name string) (*types.Secret, error) {
	all, err := r.querySecrets(ctx, `SELECT `+secretColumns+` FROM public.secret WHERE name = @name`,
		pgx.NamedArgs{"name": name})
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, errors.New("no secret has this name")
	}
	return all[0], nil
}

// ListSecrets implements repository.SecretStore.
func (r *PostgresRepository) ListSecrets(ctx context.Context) ([]*types.Secret, error) {
	return r.querySecrets(ctx, `SELECT `+secretColumns+` FROM public.secret ORDER BY name`, pgx.NamedArgs{})
}

// DeleteSecret implements repository.SecretStore.
func (r *PostgresRepository) DeleteSecret(ctx context.Context, name string) error {
	j := NewExecJob(ctx, `DELETE FROM public.secret WHERE name = @name`, pgx.NamedArgs{"name": name},
		func(pgconn.CommandTag) error { return nil })
	r.wpool.Submit(j)
	return j.Wait()
}

func (r *PostgresRepository) querySecrets(ctx context.Context, query string, args pgx.NamedArgs) ([]*types.Secret, error) {
	var out []*types.Secret
	j := NewRowsJob(ctx, query, args, func(rows pgx.Rows) error {
		for rows.Next() {
			var s types.Secret
			if err := rows.Scan(&s.Name, &s.Ciphertext, &s.Nonce, &s.KeyID, &s.UpdatedAt, &s.UpdatedBy); err != nil {
				return err
			}
			s.UpdatedAt = s.UpdatedAt.In(time.UTC).Local()
			out = append(out, &s)
		}
		return rows.Err()
	})
	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}
	return out, nil
}
