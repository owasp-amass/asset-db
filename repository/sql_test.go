package repository

import (
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	pgmigrations "github.com/owasp-amass/asset-db/migrations/postgres"
	sqlitemigrations "github.com/owasp-amass/asset-db/migrations/sqlite3"
	migrate "github.com/rubenv/sql-migrate"
	"github.com/stretchr/testify/assert"

	"github.com/glebarez/sqlite"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
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

	ip, _ := netip.ParseAddr("192.168.1.100")
	dest2 := network.IPAddress{Address: ip, Type: "IPv4"}
	rel2 := "a_record"

	dest2Asset, err := store.CreateAsset(dest2)
	if err != nil {
		t.Fatalf("failed to create asset: %s", err)
	}

	_, err = store.Link(sourceAsset, rel1, dest1Asset)
	assert.NoError(t, err)
	r2Rel, err := store.Link(sourceAsset, rel2, dest2Asset)
	assert.NoError(t, err)

	// Outgoing relations with no filter returns all outgoing relations.
	outs, err := store.OutgoingRelations(sourceAsset, time.Time{})
	assert.NoError(t, err)
	assert.Equal(t, len(outs), 2)

	// Outgoing relations with a filter returns
	outs, err = store.OutgoingRelations(sourceAsset, time.Time{}, rel1)
	assert.NoError(t, err)
	assert.Equal(t, sourceAsset.ID, outs[0].FromAsset.ID)
	assert.Equal(t, rel1, outs[0].Type)
	assert.Equal(t, dest1Asset.ID, outs[0].ToAsset.ID)

	// Incoming relations with a filter returns
	ins, err := store.IncomingRelations(dest1Asset, time.Time{}, rel1)
	assert.NoError(t, err)
	assert.Equal(t, sourceAsset.ID, ins[0].FromAsset.ID)
	assert.Equal(t, rel1, ins[0].Type)
	assert.Equal(t, dest1Asset.ID, ins[0].ToAsset.ID)

	// Outgoing with source -> a_record -> dest2Asset
	outs, err = store.OutgoingRelations(sourceAsset, time.Time{}, rel2)
	assert.NoError(t, err)
	assert.Equal(t, sourceAsset.ID, outs[0].FromAsset.ID)
	assert.Equal(t, rel2, outs[0].Type)
	assert.Equal(t, dest2Asset.ID, outs[0].ToAsset.ID)

	// Incoming for source -> a_record -> dest2asset
	ins, err = store.IncomingRelations(dest2Asset, time.Time{}, rel2)
	assert.NoError(t, err)
	assert.Equal(t, sourceAsset.ID, ins[0].FromAsset.ID)
	assert.Equal(t, rel2, ins[0].Type)
	assert.Equal(t, dest2Asset.ID, ins[0].ToAsset.ID)

	// Nanoseconds are truncated by the database; sleep for 1s
	time.Sleep(1000 * time.Millisecond)

	// Store a duplicate relation and validate last_seen is updated
	rr, err := store.Link(sourceAsset, rel2, dest2Asset)
	assert.NoError(t, err)
	assert.NotNil(t, rr)
	if rr.LastSeen.UnixNano() <= r2Rel.LastSeen.UnixNano() {
		t.Errorf("rr.LastSeen: %s, r2Rel.LastSeen: %s", rr.LastSeen.Format(time.RFC3339Nano), r2Rel.LastSeen.Format(time.RFC3339Nano))
	}
}

func TestLastSeenUpdates(t *testing.T) {
	ip, _ := netip.ParseAddr("45.73.25.1")
	asset := network.IPAddress{Address: ip, Type: "IPv4"}
	a1, err := store.CreateAsset(asset)
	assert.NoError(t, err)

	// Nanoseconds are truncated by the database, so we need to sleep for a bit.
	time.Sleep(1000 * time.Millisecond)

	a2, err := store.CreateAsset(asset)
	assert.NoError(t, err)

	assert.Equal(t, a1.ID, a2.ID)
	// assert.NotEqual(t, time.Time{}, a1.CreatedAt)
	assert.Equal(t, a1.CreatedAt, a2.CreatedAt)
	if a2.LastSeen.UnixNano() <= a1.LastSeen.UnixNano() {
		t.Errorf("a2.LastSeen: %s, a1.LastSeen: %s", a2.LastSeen.Format(time.RFC3339Nano), a1.LastSeen.Format(time.RFC3339Nano))
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
			destinationAsset: network.IPAddress{Address: ip2, Type: "IPv4"},
			relation:         "a_record",
		},
		{
			description:      "create an Autonomous System and link it with a Netblock",
			sourceAsset:      network.AutonomousSystem{Number: 2},
			destinationAsset: network.Netblock{Cidr: cidr2, Type: "IPv4"},
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

			foundAsset, err := store.FindAssetById(sourceAsset.ID, start)
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

			foundAssetByContent, err := store.FindAssetByContent(sourceAsset.Asset, start)
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

			foundAssetByType, err := store.FindAssetByType(sourceAsset.Asset.AssetType(), start)
			if err != nil {
				t.Fatalf("failed to find asset by type: %s", err)
			}

			if len(foundAssetByType) == 0 {
				t.Fatalf("failed to find assets by type: 0 assets found")
			}

			var found bool
			for _, a := range foundAssetByType {
				if a.ID == sourceAsset.ID {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("failed to find asset by type: did not receive asset of id %s", sourceAsset.ID)
			}

			found = false
			for _, a := range foundAssetByType {
				if a.Asset == sourceAsset.Asset {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("failed to find asset by type: did not receive asset %s", sourceAsset.Asset)
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

			incoming, err := store.IncomingRelations(destinationAsset, start, tc.relation)
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

			outgoing, err := store.OutgoingRelations(sourceAsset, start, tc.relation)
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

			err = store.DeleteRelation(relation.ID)
			if err != nil {
				t.Fatalf("failed to delete relation: %s", err)
			}

			err = store.DeleteAsset(destinationAsset.ID)
			if err != nil {
				t.Fatalf("failed to delete asset: %s", err)
			}

			if _, err = store.FindAssetById(destinationAsset.ID, start); err == nil {
				t.Fatal("failed to delete asset: the asset was not removed from the database")
			}
		})
	}
}
