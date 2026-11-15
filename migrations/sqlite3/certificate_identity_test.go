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

// Migration 004 keeps stored certificates and their entities, lets two
// issuers' certificates share a serial number, and Down merges them again.
func TestCertificateIdentityMigrationKeepsData(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "m.db")+"?_pragma=foreign_keys(ON)")
	require.NoError(t, err, "opening the database")
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)

	src := migrate.EmbedFileSystemMigrationSource{FileSystem: Migrations(), Root: "/"}
	_, err = migrate.ExecMax(db, "sqlite3", src, migrate.Up, 3)
	require.NoError(t, err, "migrating to 003")

	count := func(q string) int {
		t.Helper()
		var n int
		require.NoError(t, db.QueryRow(q).Scan(&n), q)
		return n
	}
	insert := `INSERT INTO tlscertificate(serial_number, subject_common_name, attrs) VALUES ('1', ?, ?)`
	_, err = db.Exec(insert, "printer.example.edu", `{"issuer_common_name":"printer.example.edu"}`)
	require.NoError(t, err, "storing a certificate before the migration")

	_, err = migrate.ExecMax(db, "sqlite3", src, migrate.Up, 1)
	require.NoError(t, err, "migrating to 004")
	assert.Equal(t, 1, count(`SELECT count(*) FROM entity WHERE table_name = 'tlscertificate'
		AND natural_key = '1|printer.example.edu||'`), "the entity's natural key should become the identity")

	_, err = db.Exec(insert+` ON CONFLICT(cert_key) DO NOTHING`, "router.other.net",
		`{"issuer_common_name":"router.other.net"}`)
	require.NoError(t, err, "storing another issuer's certificate with the same serial")
	assert.Equal(t, 2, count(`SELECT count(*) FROM tlscertificate`), "two issuers' certificates are two rows")
	assert.Equal(t, 2, count(`SELECT count(*) FROM entity WHERE table_name = 'tlscertificate'`),
		"each certificate has its entity")

	_, err = migrate.ExecMax(db, "sqlite3", src, migrate.Down, 1)
	require.NoError(t, err, "migrating back to 003")
	assert.Equal(t, 1, count(`SELECT count(*) FROM tlscertificate`), "Down keeps one certificate per serial")
	assert.Equal(t, 1, count(`SELECT count(*) FROM entity WHERE table_name = 'tlscertificate' AND natural_key = '1'`),
		"Down keys the remaining entity by serial again")
}
