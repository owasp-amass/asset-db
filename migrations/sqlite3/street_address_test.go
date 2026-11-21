// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"database/sql"
	"path/filepath"
	"testing"

	migrate "github.com/rubenv/sql-migrate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// Migration 009 renames Location to StreetAddress: a stored address keeps its
// entity ID and edges, the plain address edges become street_address, new
// writes reach the entity through the renamed table, and Down restores the old
// names.
func TestStreetAddressMigrationKeepsData(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "m.db")+"?_pragma=foreign_keys(ON)")
	require.NoError(t, err, "opening the database")
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)

	src := migrate.EmbedFileSystemMigrationSource{FileSystem: Migrations(), Root: "/"}
	_, err = migrate.ExecMax(db, "sqlite3", src, migrate.Up, 8)
	require.NoError(t, err, "migrating to 008")

	count := func(q string) int {
		t.Helper()
		var n int
		require.NoError(t, db.QueryRow(q).Scan(&n), q)
		return n
	}
	entityID := func(table string) int64 {
		t.Helper()
		var id int64
		require.NoError(t, db.QueryRow(`SELECT entity_id FROM entity WHERE table_name = ?`, table).Scan(&id))
		return id
	}

	_, err = db.Exec(`INSERT INTO location(street_address, city, country) VALUES ('1 Main St, Utica, NY', 'Utica', 'US')`)
	require.NoError(t, err, "storing an address before the migration")
	before := entityID("location")

	// an organization's and a person's plain address edges
	for _, src := range []struct{ etype, label string }{{"organization", "location"}, {"person", "address"}} {
		res, err := db.Exec(`INSERT INTO entity(etype_id, natural_key, table_name, row_id)
			VALUES ((SELECT id FROM entity_type_lu WHERE name = ?), ?, ?, 1)`, src.etype, src.etype, src.etype)
		require.NoError(t, err, "storing the %s entity", src.etype)
		from, _ := res.LastInsertId()
		_, err = db.Exec(`INSERT INTO edge(etype_id, label, content, from_entity_id, to_entity_id)
			VALUES ((SELECT id FROM edge_type_lu WHERE name = 'simplerelation'), ?, json_object('label', ?), ?, ?)`,
			src.label, src.label, from, before)
		require.NoError(t, err, "storing the %s edge", src.label)
	}

	_, err = migrate.ExecMax(db, "sqlite3", src, migrate.Up, 1)
	require.NoError(t, err, "migrating to 009")
	assert.Equal(t, before, entityID("streetaddress"), "the address keeps its entity")
	assert.Equal(t, 1, count(`SELECT count(*) FROM entity_type_lu WHERE name = 'streetaddress'`))
	assert.Equal(t, 0, count(`SELECT count(*) FROM entity_type_lu WHERE name = 'location'`))
	assert.Equal(t, 0, count(`SELECT count(*) FROM entity WHERE table_name = 'location'`))
	assert.Equal(t, 2, count(`SELECT count(*) FROM edge WHERE label = 'street_address'
		AND json_extract(content, '$.label') = 'street_address'`), "the address edges are street_address")

	_, err = db.Exec(`INSERT INTO streetaddress(street_address, city, country) VALUES ('2 Main St, Utica, NY', 'Utica', 'US')`)
	require.NoError(t, err, "storing an address after the migration")
	assert.Equal(t, 2, count(`SELECT count(*) FROM entity e JOIN entity_type_lu t ON t.id = e.etype_id
		WHERE t.name = 'streetaddress' AND e.table_name = 'streetaddress'`), "the triggers write the renamed type")

	_, err = migrate.ExecMax(db, "sqlite3", src, migrate.Down, 1)
	require.NoError(t, err, "migrating back to 008")
	assert.Equal(t, 2, count(`SELECT count(*) FROM location`), "Down keeps the addresses")
	assert.Equal(t, 1, count(`SELECT count(*) FROM edge WHERE label = 'location'
		AND json_extract(content, '$.label') = 'location'`), "Down restores the organization's location edge")
	assert.Equal(t, 1, count(`SELECT count(*) FROM edge WHERE label = 'address'
		AND json_extract(content, '$.label') = 'address'`), "Down restores the person's address edge")
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM entity WHERE entity_id = ? AND table_name = 'location'`,
		before).Scan(&n))
	assert.Equal(t, 1, n, "Down keeps the entity")
}
