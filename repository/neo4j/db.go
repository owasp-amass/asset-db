// Copyright © by Jeff Foley 2017-2026. All rights reserved.
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

// NeoRepository is a repository implementation using Neo4j as the underlying DBMS.
type NeoRepository struct {
	DB     neo4jdb.DriverWithContext
	dbname string
}

// New creates a new instance of the asset database repository.
func New(dbtype, dsn string) (*NeoRepository, error) {
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

	return &NeoRepository{
		DB:     driver,
		dbname: dbname,
	}, driver.VerifyConnectivity(ctx)
}

// GetDBType returns the type of the database.
func (neo *NeoRepository) GetDBType() string {
	return Neo4j
}

// Prepare prepares the repository for use.
func (neo *NeoRepository) Prepare(ctx context.Context) error {
	return nil
}

// Close implements the Repository interface.
func (neo *NeoRepository) Close() error {
	return neo.DB.Close(context.Background())
}
