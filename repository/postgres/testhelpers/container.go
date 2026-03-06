// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package testhelpers

import (
	"context"

	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

type PostgresContainer struct {
	*postgres.PostgresContainer
	ConnectionString string
}

func CreatePostgresContainer(ctx context.Context) (*PostgresContainer, error) {
	const (
		dbName = "assetdb"
		user   = "amass"
		pass   = "amasspass"
	)

	pgContainer, err := postgres.Run(ctx,
		"postgres:17.7-alpine",
		postgres.WithDatabase(dbName),
		postgres.WithUsername(user),
		postgres.WithPassword(pass),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		return nil, err
	}

	connStr, err := pgContainer.ConnectionString(ctx,
		"timezone=UTC",
		"sslmode=disable",
		"connect_timeout=5",
		"lock_timeout=5000",
		"statement_timeout=60000",
		"statement_cache_capacity=256",
		"application_name=assetdbtests",
	)
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		return nil, err
	}

	return &PostgresContainer{
		PostgresContainer: pgContainer,
		ConnectionString:  connStr,
	}, nil
}
