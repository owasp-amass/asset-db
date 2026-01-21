// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"log"

	"github.com/owasp-amass/asset-db/repository/postgres/testhelpers"
)

func setupContainerAndPostgresRepo() (*testhelpers.PostgresContainer, *PostgresRepository, error) {
	pgContainer, err := testhelpers.CreatePostgresContainer(context.Background())
	if err != nil {
		return nil, nil, err
	}

	repository, err := New("postgres", pgContainer.ConnectionString)
	if err != nil {
		return nil, nil, err
	}

	return pgContainer, repository, nil
}

func LogDatabaseState(repo *PostgresRepository) {
	p := repo.pool.pool
	st := p.Stat()
	cfg := p.Config()
	cc := cfg.ConnConfig

	log.Printf("pool endpoint host=%q port=%d db=%q user=%q", cc.Host, cc.Port, cc.Database, cc.User)

	log.Printf("pool stat: total=%d idle=%d acquired=%d constructing=%d max=%d",
		st.TotalConns(), st.IdleConns(), st.AcquiredConns(), st.ConstructingConns(), st.MaxConns())
}
