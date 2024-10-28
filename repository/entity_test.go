// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	pgmigrations "github.com/owasp-amass/asset-db/migrations/postgres"
	sqlitemigrations "github.com/owasp-amass/asset-db/migrations/sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/relation"
	migrate "github.com/rubenv/sql-migrate"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var store *sqlRepository

type testSetup struct {
	name     DBType
	dsn      string
	setup    func(string) (*gorm.DB, error)
	teardown func(string)
}

func setupSqlite(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	migrationsSource := migrate.EmbedFileSystemMigrationSource{
		FileSystem: sqlitemigrations.Migrations(),
		Root:       "/",
	}

	sqlDb, err := db.DB()
	if err != nil {
		return nil, err
	}

	_, err = migrate.Exec(sqlDb, "sqlite3", migrationsSource, migrate.Up)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func teardownSqlite(dsn string) {
	err := os.Remove(dsn)
	if err != nil {
		panic(err)
	}
}

func setupPostgres(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	migrationsSource := migrate.EmbedFileSystemMigrationSource{
		FileSystem: pgmigrations.Migrations(),
		Root:       "/",
	}

	sqlDb, err := db.DB()
	if err != nil {
		return nil, err
	}

	_, err = migrate.Exec(sqlDb, "postgres", migrationsSource, migrate.Up)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func teardownPostgres(dsn string) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	migrationsSource := migrate.EmbedFileSystemMigrationSource{
		FileSystem: pgmigrations.Migrations(),
		Root:       "/",
	}

	sqlDb, err := db.DB()
	if err != nil {
		panic(err)
	}

	_, err = migrate.Exec(sqlDb, "postgres", migrationsSource, migrate.Down)
	if err != nil {
		panic(err)
	}
}

func TestMain(m *testing.M) {
	user := "postgres"
	if u, ok := os.LookupEnv("POSTGRES_USER"); ok {
		user = u
	}

	password := "postgres"
	if p, ok := os.LookupEnv("POSTGRES_PASSWORD"); ok {
		password = p
	}

	pgdbname := "postgres"
	if pdb, ok := os.LookupEnv("POSTGRES_DB"); ok {
		pgdbname = pdb
	}

	sqlitedbname := "test.db"
	if sdb, ok := os.LookupEnv("SQLITE3_DB"); ok {
		sqlitedbname = sdb
	}

	wrappers := []testSetup{
		{
			name:     Postgres,
			setup:    setupPostgres,
			dsn:      fmt.Sprintf("host=localhost port=5432 user=%s password=%s dbname=%s", user, password, pgdbname),
			teardown: teardownPostgres,
		},
		{
			name:     SQLite,
			setup:    setupSqlite,
			dsn:      sqlitedbname,
			teardown: teardownSqlite,
		},
	}

	exitCodes := make([]int, len(wrappers))

	for i, w := range wrappers {
		_, err := w.setup(w.dsn)
		if err != nil {
			panic(err)
		}

		store = New(w.name, w.dsn)
		exitCodes[i] = m.Run()
		if w.teardown != nil {
			w.teardown(w.dsn)
		}
	}

	for _, exitCode := range exitCodes {
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	}

	os.Exit(0)
}

func TestLastSeenUpdates(t *testing.T) {
	ip, _ := netip.ParseAddr("45.73.25.1")
	asset := network.IPAddress{Address: ip, Type: "IPv4"}
	a1, err := store.CreateEntity(asset)
	assert.NoError(t, err)

	// Nanoseconds are truncated by the database, so we need to sleep for a bit.
	time.Sleep(1000 * time.Millisecond)

	a2, err := store.CreateEntity(asset)
	assert.NoError(t, err)
	assert.Equal(t, a1.ID, a2.ID)
	assert.Equal(t, a1.CreatedAt, a2.CreatedAt)
	assert.Equal(t, a1.LastSeen, a2.LastSeen)

	err = store.UpdateEntityLastSeen(a1.ID)
	assert.NoError(t, err)
	a3, _ := store.CreateEntity(asset)
	assert.NoError(t, err)
	if a3.LastSeen.UnixNano() <= a1.LastSeen.UnixNano() {
		t.Errorf("a3.LastSeen: %s, a1.LastSeen: %s", a2.LastSeen.Format(time.RFC3339Nano), a1.LastSeen.Format(time.RFC3339Nano))
	}
}

func TestRepository(t *testing.T) {
	start := time.Now().Truncate(time.Hour)
	ip, _ := netip.ParseAddr("192.168.1.1")
	ip2, _ := netip.ParseAddr("192.168.1.2")
	cidr, _ := netip.ParsePrefix("198.51.100.0/24")
	cidr2, _ := netip.ParsePrefix("198.52.100.0/24")

	testCases := []struct {
		description      string
		sourceAsset      oam.Asset
		destinationAsset oam.Asset
		relation         string
	}{
		{
			description:      "create an FQDN and link it with another FQDN",
			sourceAsset:      &domain.FQDN{Name: "www.example.com"},
			destinationAsset: &domain.FQDN{Name: "www.example.subdomain.com"},
			relation:         "cname_record",
		},
		{
			description:      "create an Autonomous System and link it with an RIR organization",
			sourceAsset:      &network.AutonomousSystem{Number: 1},
			destinationAsset: &oamreg.AutnumRecord{Number: 1, Handle: "AS1", Name: "GOGL"},
			relation:         "registration",
		},
		{
			description:      "create a Netblock and link it with an IP address",
			sourceAsset:      &network.Netblock{CIDR: cidr, Type: "IPv4"},
			destinationAsset: &network.IPAddress{Address: ip, Type: "IPv4"},
			relation:         "contains",
		},
		{
			description:      "create an FQDN and link it with an IP address",
			sourceAsset:      &domain.FQDN{Name: "www.domain.com"},
			destinationAsset: &network.IPAddress{Address: ip2, Type: "IPv4"},
			relation:         "a_record",
		},
		{
			description:      "create an Autonomous System and link it with a Netblock",
			sourceAsset:      &network.AutonomousSystem{Number: 2},
			destinationAsset: &network.Netblock{CIDR: cidr2, Type: "IPv4"},
			relation:         "announces",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			sourceEntity, err := store.CreateEntity(tc.sourceAsset)
			if err != nil {
				t.Fatalf("failed to create entity: %s", err)
			}

			if sourceEntity == nil {
				t.Fatalf("failed to create entity: entity is nil")
			}

			foundAsset, err := store.FindEntityById(sourceEntity.ID, start)
			if err != nil {
				t.Fatalf("failed to find entity by id: %s", err)
			}

			if foundAsset == nil {
				t.Fatalf("failed to find entity by id: found entity is nil")
			}

			if foundAsset.ID != sourceEntity.ID {
				t.Fatalf("failed to find entity by id: expected entity id %s, got %s", sourceEntity.ID, foundAsset.ID)
			}

			if !reflect.DeepEqual(foundAsset.Asset, sourceEntity.Asset) {
				t.Fatalf("failed to find entity by id: expected entity %s, got %s", sourceEntity.Asset, foundAsset.Asset)
			}

			foundAssetByContent, err := store.FindEntityByContent(sourceEntity.Asset, start)
			if err != nil {
				t.Fatalf("failed to find entity by content: %s", err)
			}

			if foundAssetByContent == nil {
				t.Fatalf("failed to find entity by content: found entity is nil")
			}

			if foundAssetByContent[0].ID != sourceEntity.ID {
				t.Fatalf("failed to find entity by content: expected entity id %s, got %s", sourceEntity.ID, foundAssetByContent[0].ID)
			}

			if !reflect.DeepEqual(foundAssetByContent[0].Asset, sourceEntity.Asset) {
				t.Fatalf("failed to find entity by content: expected entity %s, got %s", sourceEntity.Asset, foundAssetByContent[0].Asset)
			}

			foundEntityByType, err := store.FindEntitiesByType(sourceEntity.Asset.AssetType(), start)
			if err != nil {
				t.Fatalf("failed to find entity by type: %s", err)
			}

			if len(foundEntityByType) == 0 {
				t.Fatalf("failed to find entities by type: 0 entities found")
			}

			var found bool
			for _, e := range foundEntityByType {
				if e.ID == sourceEntity.ID {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("failed to find entity by type: did not receive entity of id %s", sourceEntity.ID)
			}

			found = false
			for _, e := range foundEntityByType {
				if reflect.DeepEqual(e.Asset, sourceEntity.Asset) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("failed to find entity by type: did not receive entity %s", sourceEntity.Asset)
			}

			destinationEntity, err := store.CreateEntity(tc.destinationAsset)
			if err != nil {
				t.Fatalf("failed to create destination entity: %s", err)
			}

			if destinationEntity == nil {
				t.Fatalf("failed to create destination entity: destination entity is nil")
			}

			edge := &types.Edge{
				Relation:   relation.SimpleRelation{Name: tc.relation},
				FromEntity: sourceEntity,
				ToEntity:   destinationEntity,
			}

			e, err := store.Link(edge)
			if err != nil {
				t.Fatalf("failed to link entities: %s", err)
			}

			if e == nil {
				t.Fatalf("failed to link entities: edge is nil")
			}

			incoming, err := store.IncomingEdges(destinationEntity, start, tc.relation)
			if err != nil {
				t.Fatalf("failed to query incoming edges: %s", err)
			}

			if incoming == nil {
				t.Fatalf("failed to query incoming edges: incoming edge is nil %s", err)
			}

			if incoming[0].Relation.Label() != tc.relation {
				t.Fatalf("failed to query incoming edges: expected relation %s, got %s", tc.relation, incoming[0].Relation.Label())
			}

			if incoming[0].FromEntity.ID != sourceEntity.ID {
				t.Fatalf("failed to query incoming edges: expected source entity id %s, got %v", sourceEntity.ID, incoming[0].FromEntity.ID)
			}

			if incoming[0].ToEntity.ID != destinationEntity.ID {
				t.Fatalf("failed to query incoming edges: expected destination entity id %s, got %s", destinationEntity.ID, incoming[0].ToEntity.ID)
			}

			outgoing, err := store.OutgoingEdges(sourceEntity, start, tc.relation)
			if err != nil {
				t.Fatalf("failed to query outgoing edges: %s", err)
			}

			if outgoing == nil {
				t.Fatalf("failed to query outgoing edges: outgoing edge is nil")
			}

			if outgoing[0].Relation.Label() != tc.relation {
				t.Fatalf("failed to query outgoing edges: expected edge %s, got %s", tc.relation, outgoing[0].Relation.Label())
			}

			if outgoing[0].FromEntity.ID != sourceEntity.ID {
				t.Fatalf("failed to query outgoing edges: expected source entity id %s, got %s", sourceEntity.ID, outgoing[0].FromEntity.ID)
			}

			if outgoing[0].ToEntity.ID != destinationEntity.ID {
				t.Fatalf("failed to query outgoing edges: expected destination entity id %s, got %s", destinationEntity.ID, outgoing[0].ToEntity.ID)
			}

			err = store.DeleteEdge(e.ID)
			if err != nil {
				t.Fatalf("failed to delete edges: %s", err)
			}

			err = store.DeleteEntity(destinationEntity.ID)
			if err != nil {
				t.Fatalf("failed to delete asset: %s", err)
			}

			if _, err = store.FindEntityById(destinationEntity.ID, start); err == nil {
				t.Fatal("failed to delete entity: the entity was not removed from the database")
			}
		})
	}
}

func TestGetDBType(t *testing.T) {
	sql := &sqlRepository{
		dbType: "postgres",
	}

	expected := "postgres"
	result := sql.GetDBType()

	if result != expected {
		t.Errorf("Unexpected result. Expected: %s, Got: %s", expected, result)
	}
}
