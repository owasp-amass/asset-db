// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assetdb

import (
	"context"
	"fmt"
	"time"

	neomigrations "github.com/owasp-amass/asset-db/migrations/neo4j"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/neo4j"
)

// New creates a new assetDB instance.
// It initializes the asset database with the specified database type and DSN.
func New(dbtype, dsn string) (repository.Repository, error) {
	db, err := repository.New(dbtype, dsn)
	if err != nil {
		return nil, err
	}

	if err := migrateDatabase(dbtype, db); err != nil {
		return nil, err
	}

	return db, nil
}

func migrateDatabase(dbtype string, repo repository.Repository) error {
	switch dbtype {
	case neo4j.Neo4j:
		return neoMigrate(repo)
	}
	return nil
}

func neoMigrate(repo repository.Repository) error {
	r, ok := repo.(*neo4j.NeoRepository)
	if !ok {
		return fmt.Errorf("failed to cast repository to neoRepository")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := r.DB.VerifyConnectivity(ctx); err != nil {
		return err
	}

	return neomigrations.InitializeSchema(r.DB, "neo4j")
}
