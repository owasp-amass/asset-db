// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package testhelpers

import (
	"context"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
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

	waitSQL := wait.ForSQL("5432/tcp", "pgx", func(host string, port nat.Port) string {
		// This DSN is used only for the wait check.
		// Keep it minimal and reliable.
		return "postgres://" + user + ":" + pass + "@" + host + ":" + port.Port() + "/" + dbName + "?sslmode=disable"
	}).WithStartupTimeout(60 * time.Second)

	pgContainer, err := postgres.Run(ctx,
		"postgres:17.7-alpine",
		postgres.WithDatabase(dbName),
		postgres.WithUsername(user),
		postgres.WithPassword(pass),
		testcontainers.WithWaitStrategy(
			wait.ForAll(
				wait.ForListeningPort("5432/tcp").WithStartupTimeout(60*time.Second),
				waitSQL,
			),
		),
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
