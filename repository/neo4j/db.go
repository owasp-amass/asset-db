// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j/config"
)

const Neo4j string = "neo4j"

// neoRepository is a repository implementation using Neo4j as the underlying DBMS.
type neoRepository struct {
	db     neo4jdb.DriverWithContext
	dbname string
}

// New creates a new instance of the asset database repository.
func New(dbtype, dsn string) (*neoRepository, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, err
	}

	auth := neo4jdb.NoAuth()
	var username, password string
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
		auth = neo4jdb.BasicAuth(username, password, "")
	}
	dbname := strings.TrimPrefix(u.Path, "/")

	newdsn := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	driver, err := neo4jdb.NewDriverWithContext(newdsn, auth, func(cfg *config.Config) {
		cfg.MaxConnectionPoolSize = 20
		cfg.MaxConnectionLifetime = time.Hour
		cfg.ConnectionLivenessCheckTimeout = 10 * time.Minute
	})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return &neoRepository{
		db:     driver,
		dbname: dbname,
	}, driver.VerifyConnectivity(ctx)
}

// Close implements the Repository interface.
func (neo *neoRepository) Close() error {
	return neo.db.Close(context.Background())
}

// GetDBType returns the type of the database.
func (neo *neoRepository) GetDBType() string {
	return Neo4j
}
