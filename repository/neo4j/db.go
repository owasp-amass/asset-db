// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"
	"time"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

const Neo4j string = "neo4j"

// neoRepository is a repository implementation using Neo4j as the underlying DBMS.
type neoRepository struct {
	db neo4jdb.DriverWithContext
}

// New creates a new instance of the asset database repository.
func New(dbtype, dsn string) (*neoRepository, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	driver, err := neo4jdb.NewDriverWithContext(dsn, neo4jdb.NoAuth(), func(config *neo4jdb.Config) {
		config.MaxConnectionPoolSize = 10
	})
	if err != nil {
		return nil, err
	}

	return &neoRepository{db: driver}, driver.VerifyConnectivity(ctx)
}

// Close implements the Repository interface.
func (neo *neoRepository) Close() error {
	return neo.db.Close(context.Background())
}

// GetDBType returns the type of the database.
func (neo *neoRepository) GetDBType() string {
	return Neo4j
}
