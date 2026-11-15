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

// Migration 003 on a database with data: source tags are merged, edges and
// their tags survive the edge table's rebuild, DNS edges become distinct per
// record type, and Down returns the earlier schema.
func TestLeanIndexesMigrationKeepsData(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "m.db")+"?_pragma=foreign_keys(ON)")
	require.NoError(t, err, "opening the database")
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)

	src := migrate.EmbedFileSystemMigrationSource{FileSystem: Migrations(), Root: "/"}
	_, err = migrate.ExecMax(db, "sqlite3", src, migrate.Up, 2)
	require.NoError(t, err, "migrating to 002")

	exec := func(q string, args ...any) {
		t.Helper()
		_, err := db.Exec(q, args...)
		require.NoError(t, err, q)
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		require.NoError(t, db.QueryRow(q, args...).Scan(&n), q)
		return n
	}

	exec(`INSERT INTO fqdn(fqdn) VALUES ('a.example.org'), ('b.example.org')`)
	var a, b int64
	require.NoError(t, db.QueryRow(`SELECT entity_id FROM entity WHERE natural_key = 'a.example.org'`).Scan(&a))
	require.NoError(t, db.QueryRow(`SELECT entity_id FROM entity WHERE natural_key = 'b.example.org'`).Scan(&b))
	exec(`INSERT INTO edge(etype_id, label, from_entity_id, to_entity_id, content)
		VALUES ((SELECT id FROM edge_type_lu WHERE name = 'basicdnsrelation'), 'dns_record', ?, ?,
		'{"header":{"rr_type":2}}')`, a, b)
	var edgeID int64
	require.NoError(t, db.QueryRow(`SELECT edge_id FROM edge`).Scan(&edgeID))
	src3 := `(SELECT id FROM tag_type_lu WHERE name = 'sourceproperty')`
	exec(`INSERT INTO edge_tag(edge_id, ttype_id, property_name, property_value, content)
		VALUES (?, `+src3+`, 'DNS', '100', '{"name":"DNS","confidence":100}')`, edgeID)
	exec(`INSERT INTO entity_tag(entity_id, ttype_id, property_name, property_value, content, updated_at)
		VALUES (?, `+src3+`, 'crt.sh', '90', '{"name":"crt.sh","confidence":90}', '2026-01-01 00:00:00')`, a)
	exec(`INSERT INTO entity_tag(entity_id, ttype_id, property_name, property_value, content, updated_at)
		VALUES (?, `+src3+`, 'crt.sh', '100', '{"name":"crt.sh","confidence":100}', '2026-02-01 00:00:00')`, a)

	_, err = migrate.ExecMax(db, "sqlite3", src, migrate.Up, 1)
	require.NoError(t, err, "migrating to 003")

	assert.Equal(t, 1, count(`SELECT count(*) FROM entity_tag WHERE property_name = 'crt.sh'`),
		"duplicate source tags should be merged")
	assert.Equal(t, 1, count(`SELECT count(*) FROM entity_tag WHERE property_name = 'crt.sh'
		AND json_extract(content, '$.confidence') = 100 AND property_value = ''`),
		"the latest confidence should be kept in the content")
	assert.Equal(t, 1, count(`SELECT count(*) FROM edge WHERE edge_id = ?`, edgeID), "the edge should keep its id")
	assert.Equal(t, 1, count(`SELECT count(*) FROM edge_tag WHERE edge_id = ?`, edgeID),
		"the edge's tag should survive the rebuild")
	assert.Equal(t, 0, count(`SELECT count(*) FROM pragma_foreign_key_check`), "no reference should be broken")

	// a CNAME between the same names is now its own edge
	upsert := `INSERT INTO edge(etype_id, label, from_entity_id, to_entity_id, content)
		VALUES ((SELECT id FROM edge_type_lu WHERE name = 'basicdnsrelation'), 'dns_record', ?, ?, ?)
		ON CONFLICT(from_entity_id, label, etype_id, to_entity_id, rr_type) DO UPDATE SET content = excluded.content`
	exec(upsert, a, b, `{"header":{"rr_type":5}}`)
	exec(upsert, a, b, `{"header":{"rr_type":2,"ttl":60}}`)
	assert.Equal(t, 2, count(`SELECT count(*) FROM edge`), "NS and CNAME between the same names are two edges")
	exec(`INSERT INTO edge(etype_id, label, from_entity_id, to_entity_id)
		VALUES ((SELECT id FROM edge_type_lu WHERE name = 'simplerelation'), 'node', ?, ?)`, b, a)
	var newID int64
	require.NoError(t, db.QueryRow(`SELECT max(edge_id) FROM edge`).Scan(&newID))
	assert.Greater(t, newID, edgeID+1, "new edges should continue the id sequence")

	_, err = migrate.ExecMax(db, "sqlite3", src, migrate.Down, 1)
	require.NoError(t, err, "migrating back to 002")
	assert.Equal(t, 2, count(`SELECT count(*) FROM edge`), "the DNS edges collapse to one per type and endpoints")
	assert.Equal(t, 1,
		count(`SELECT count(*) FROM entity_tag WHERE property_name = 'crt.sh' AND property_value = '100'`),
		"source tags should hold their confidence again")
	assert.Equal(t, 0, count(`SELECT count(*) FROM pragma_foreign_key_check`),
		"no reference should be broken after Down")
	assert.Equal(t, 1, count(`SELECT count(*) FROM sqlite_master WHERE name = 'idx_edge_from'`),
		"Down should restore the earlier edge indexes")
}
