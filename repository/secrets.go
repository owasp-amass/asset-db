// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"

	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	"github.com/owasp-amass/asset-db/types"
)

// SecretStore is implemented by repositories that keep secrets for the
// tools sharing the database, stored only as the tools encrypted them
// (types.Secret).
type SecretStore interface {
	// PutSecret stores a secret, replacing one of the same name, and
	// returns it with its update time.
	PutSecret(ctx context.Context, s *types.Secret) (*types.Secret, error)
	// GetSecret returns the secret with the name, or an error.
	GetSecret(ctx context.Context, name string) (*types.Secret, error)
	// ListSecrets returns every secret, by name.
	ListSecrets(ctx context.Context) ([]*types.Secret, error)
	// DeleteSecret removes the secret with the name; removing one that is
	// not there does nothing.
	DeleteSecret(ctx context.Context, name string) error
}

var (
	_ SecretStore = (*postgres.PostgresRepository)(nil)
	_ SecretStore = (*sqlite3.SqliteRepository)(nil)
)
