// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assetdb

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/owasp-amass/asset-db/repository/neo4j"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

func TestNewSQLite(t *testing.T) {
	db, err := New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assetdb.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if db.Type() != sqlite3.SQLite {
		t.Errorf("database type = %q", db.Type())
	}
	ent, err := db.CreateAsset(context.Background(), &oamdns.FQDN{Name: "example.com"})
	if err != nil || ent == nil {
		t.Fatalf("CreateAsset: %v", err)
	}
}

func TestNewUnknownType(t *testing.T) {
	if db, err := New("oracle", "dsn"); err == nil || db != nil {
		t.Errorf("New with an unknown type = %v, %v; want an error", db, err)
	}
}

// Only a Neo4j repository is migrated here; the SQL backends migrate
// themselves when opened.
func TestMigrateDatabase(t *testing.T) {
	db, err := sqlite3.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assetdb.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if err := migrateDatabase(sqlite3.SQLite, db); err != nil {
		t.Errorf("migrating SQLite: %v", err)
	}
	if err := migrateDatabase(neo4j.Neo4j, db); err == nil {
		t.Error("a SQLite repository was accepted as a Neo4j one")
	}
}

// TestNewNeo4j opens a live Neo4j database and applies the schema. It runs
// only with ASSETDB_NEO4J_TEST_DSN set, such as
// bolt://neo4j:password@localhost:7687/assetdb.
func TestNewNeo4j(t *testing.T) {
	dsn := os.Getenv("ASSETDB_NEO4J_TEST_DSN")
	if dsn == "" {
		t.Skip("ASSETDB_NEO4J_TEST_DSN is not set")
	}
	db, err := New(neo4j.Neo4j, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// the schema can be applied again without error
	if err := migrateDatabase(neo4j.Neo4j, db); err != nil {
		t.Errorf("applying the schema a second time: %v", err)
	}
}
