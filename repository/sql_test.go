package repository

import (
	"fmt"
	"net/netip"
	"os"
	"testing"

	pgmigrations "github.com/owasp-amass/asset-db/migrations/postgres"
	sqlitemigrations "github.com/owasp-amass/asset-db/migrations/sqlite3"
	migrate "github.com/rubenv/sql-migrate"
	"github.com/stretchr/testify/assert"

	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var user = os.Getenv("POSTGRES_USER")
var password = os.Getenv("POSTGRES_PASSWORD")
var pgdbname = os.Getenv("POSTGRES_DB")
var sqlitedbname = os.Getenv("SQLITE3_DB")

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
		FileSystem: sqlitemigrations.Migrations(),
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

func TestUnfilteredRelations(t *testing.T) {
	source := domain.FQDN{Name: "owasp.com"}
	dest1 := domain.FQDN{Name: "www.example.owasp.org"}
	rel1 := "cname_record"

	sourceAsset, err := store.CreateAsset(source)
	if err != nil {
		t.Fatalf("failed to create asset: %s", err)
	}

	dest1Asset, err := store.CreateAsset(dest1)
	if err != nil {
		t.Fatalf("failed to create asset: %s", err)
	}

	ip, _ := netip.ParseAddr("192.168.1.1")
	dest2 := network.IPAddress{Address: ip, Type: "IPv4"}
	rel2 := "a_record"

	dest2Asset, err := store.CreateAsset(dest2)
	if err != nil {
		t.Fatalf("failed to create asset: %s", err)
	}

	_, err = store.Link(sourceAsset, rel1, dest1Asset)
	assert.NoError(t, err)
	_, err = store.Link(sourceAsset, rel2, dest2Asset)
	assert.NoError(t, err)

	// Outgoing relations with no filter returns all outgoing relations.
	outs, err := store.OutgoingRelations(sourceAsset)
	assert.NoError(t, err)
	assert.Equal(t, len(outs), 2)

	// Outgoing relations with a filter returns
	outs, err = store.OutgoingRelations(sourceAsset, rel1)
	assert.NoError(t, err)
	assert.Equal(t, sourceAsset.ID, outs[0].FromAsset.ID)
	assert.Equal(t, rel1, outs[0].Type)
	assert.Equal(t, dest1Asset.ID, outs[0].ToAsset.ID)

	// Incoming relations with a filter returns
	ins, err := store.IncomingRelations(dest1Asset, rel1)
	assert.NoError(t, err)
	assert.Equal(t, sourceAsset.ID, ins[0].FromAsset.ID)
	assert.Equal(t, rel1, ins[0].Type)
	assert.Equal(t, dest1Asset.ID, ins[0].ToAsset.ID)

	// Outgoing with source -> a_record -> dest2Asset
	outs, err = store.OutgoingRelations(sourceAsset, rel2)
	assert.NoError(t, err)
	assert.Equal(t, sourceAsset.ID, outs[0].FromAsset.ID)
	assert.Equal(t, rel2, outs[0].Type)
	assert.Equal(t, dest2Asset.ID, outs[0].ToAsset.ID)

	// Incoming for source -> a_record -> dest2asset
	ins, err = store.IncomingRelations(dest2Asset, rel2)
	assert.NoError(t, err)
	assert.Equal(t, sourceAsset.ID, ins[0].FromAsset.ID)
	assert.Equal(t, rel2, ins[0].Type)
	assert.Equal(t, dest2Asset.ID, ins[0].ToAsset.ID)

}

func TestRepository(t *testing.T) {
	ip, _ := netip.ParseAddr("192.168.1.1")
	cidr, _ := netip.ParsePrefix("198.51.100.0/24")

	testCases := []struct {
		description      string
		sourceAsset      oam.Asset
		destinationAsset oam.Asset
		relation         string
	}{
		{
			description:      "create an FQDN and link it with another FQDN",
			sourceAsset:      domain.FQDN{Name: "www.example.com"},
			destinationAsset: domain.FQDN{Name: "www.example.subdomain.com"},
			relation:         "cname_record",
		},
		{
			description:      "create an Autonomous System and link it with an RIR organization",
			sourceAsset:      network.AutonomousSystem{Number: 1},
			destinationAsset: network.RIROrganization{Name: "Google LLC", RIRId: "GOGL", RIR: "ARIN"},
			relation:         "managed_by",
		},
		{
			description:      "create a Netblock and link it with an IP address",
			sourceAsset:      network.Netblock{Cidr: cidr, Type: "IPv4"},
			destinationAsset: network.IPAddress{Address: ip, Type: "IPv4"},
			relation:         "contains",
		},
		{
			description:      "create an FQDN and link it with an IP address",
			sourceAsset:      domain.FQDN{Name: "www.domain.com"},
			destinationAsset: network.IPAddress{Address: ip, Type: "IPv4"},
			relation:         "a_record",
		},
		{
			description:      "create an Autonomous System and link it with an IP address",
			sourceAsset:      network.AutonomousSystem{Number: 2},
			destinationAsset: network.IPAddress{Address: ip, Type: "IPv4"},
			relation:         "announces",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			sourceAsset, err := store.CreateAsset(tc.sourceAsset)
			if err != nil {
				t.Fatalf("failed to create asset: %s", err)
			}

			if sourceAsset == nil {
				t.Fatalf("failed to create asset: asset is nil")
			}

			foundAsset, err := store.FindAssetById(sourceAsset.ID)
			if err != nil {
				t.Fatalf("failed to find asset by id: %s", err)
			}

			if foundAsset == nil {
				t.Fatalf("failed to find asset by id: found asset is nil")
			}

			if foundAsset.ID != sourceAsset.ID {
				t.Fatalf("failed to find asset by id: expected asset id %s, got %s", sourceAsset.ID, foundAsset.ID)
			}

			if foundAsset.Asset != sourceAsset.Asset {
				t.Fatalf("failed to find asset by id: expected asset %s, got %s", sourceAsset.Asset, foundAsset.Asset)
			}

			foundAssetByContent, err := store.FindAssetByContent(sourceAsset.Asset)
			if err != nil {
				t.Fatalf("failed to find asset by content: %s", err)
			}

			if foundAssetByContent == nil {
				t.Fatalf("failed to find asset by content: found asset is nil")
			}

			if foundAssetByContent[0].ID != sourceAsset.ID {
				t.Fatalf("failed to find asset by content: expected asset id %s, got %s", sourceAsset.ID, foundAssetByContent[0].ID)
			}

			if foundAssetByContent[0].Asset != sourceAsset.Asset {
				t.Fatalf("failed to find asset by content: expected asset %s, got %s", sourceAsset.Asset, foundAssetByContent[0].Asset)
			}

			destinationAsset, err := store.CreateAsset(tc.destinationAsset)
			if err != nil {
				t.Fatalf("failed to create destination asset: %s", err)
			}

			if destinationAsset == nil {
				t.Fatalf("failed to create destination asset: destination asset is nil")
			}

			relation, err := store.Link(sourceAsset, tc.relation, destinationAsset)
			if err != nil {
				t.Fatalf("failed to link assets: %s", err)
			}

			if relation == nil {
				t.Fatalf("failed to link assets: relation is nil")
			}

			incoming, err := store.IncomingRelations(destinationAsset, tc.relation)
			if err != nil {
				t.Fatalf("failed to query incoming relations: %s", err)
			}

			if incoming == nil {
				t.Fatalf("failed to query incoming relations: incoming relations is nil %s", err)
			}

			if incoming[0].Type != tc.relation {
				t.Fatalf("failed to query incoming relations: expected relation %s, got %s", tc.relation, incoming[0].Type)
			}

			if incoming[0].FromAsset.ID != sourceAsset.ID {
				t.Fatalf("failed to query incoming relations: expected source asset id %s, got %v", sourceAsset.ID, incoming[0].FromAsset.ID)
			}

			if incoming[0].ToAsset.ID != destinationAsset.ID {
				t.Fatalf("failed to query incoming relations: expected destination asset id %s, got %s", destinationAsset.ID, incoming[0].ToAsset.ID)
			}

			outgoing, err := store.OutgoingRelations(sourceAsset, tc.relation)
			if err != nil {
				t.Fatalf("failed to query outgoing relations: %s", err)
			}

			if outgoing == nil {
				t.Fatalf("failed to query outgoing relations: outgoing relations is nil")
			}

			if outgoing[0].Type != tc.relation {
				t.Fatalf("failed to query outgoing relations: expected relation %s, got %s", tc.relation, outgoing[0].Type)
			}

			if outgoing[0].FromAsset.ID != sourceAsset.ID {
				t.Fatalf("failed to query outgoing relations: expected source asset id %s, got %s", sourceAsset.ID, outgoing[0].FromAsset.ID)
			}

			if outgoing[0].ToAsset.ID != destinationAsset.ID {
				t.Fatalf("failed to query outgoing relations: expected destination asset id %s, got %s", destinationAsset.ID, outgoing[0].ToAsset.ID)
			}
		})
	}
}
