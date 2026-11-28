// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamfile "github.com/owasp-amass/open-asset-model/file"
	oamurl "github.com/owasp-amass/open-asset-model/url"
	"github.com/stretchr/testify/assert"
)

// A URL keeps the case of its path and query; its scheme and host are
// compared without case.
func TestURLKeepsItsCase(t *testing.T) {
	db, dir, err := setupTempSQLite()
	assert.NoError(t, err)
	defer teardownTempSQLite(db, dir)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	raw := "HTTPS://Files.Example.COM/Reports/Q1.PDF?Token=AbCdEf#Top"
	ent, err := db.CreateAsset(ctx, &oamurl.URL{Raw: raw, Scheme: "https", Host: "files.example.com",
		Path: "/Reports/Q1.PDF"})
	assert.NoError(t, err)
	got, err := db.FindEntityById(ctx, ent.ID)
	assert.NoError(t, err)
	assert.Equal(t, "https://files.example.com/Reports/Q1.PDF?Token=AbCdEf#Top", got.Asset.(*oamurl.URL).Raw)

	// the same URL written with another case of scheme and host is the same entity
	again, err := db.CreateAsset(ctx, &oamurl.URL{Raw: "https://FILES.example.com/Reports/Q1.PDF?Token=AbCdEf#Top",
		Scheme: "https", Host: "files.example.com", Path: "/Reports/Q1.PDF"})
	assert.NoError(t, err)
	assert.Equal(t, ent.ID, again.ID)

	// another case of the path is another URL
	other, err := db.CreateAsset(ctx, &oamurl.URL{Raw: "https://files.example.com/reports/q1.pdf?token=abcdef#top",
		Scheme: "https", Host: "files.example.com", Path: "/reports/q1.pdf"})
	assert.NoError(t, err)
	assert.NotEqual(t, ent.ID, other.ID)

	found, err := db.FindEntitiesByContent(ctx, oam.URL, time.Time{}, 0,
		dbt.ContentFilters{"url": "https://Files.Example.com/Reports/Q1.PDF?Token=AbCdEf#Top"})
	assert.NoError(t, err)
	if assert.Len(t, found, 1) {
		assert.Equal(t, ent.ID, found[0].ID)
	}
}

// A file's URL keeps its case too.
func TestFileURLKeepsItsCase(t *testing.T) {
	db, dir, err := setupTempSQLite()
	assert.NoError(t, err)
	defer teardownTempSQLite(db, dir)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ent, err := db.CreateAsset(ctx, &oamfile.File{URL: "HTTPS://Docs.Example.com/Annual/Report-2026.PDF",
		Name: "Report-2026.PDF", Type: "document"})
	assert.NoError(t, err)
	got, err := db.FindEntityById(ctx, ent.ID)
	assert.NoError(t, err)
	assert.Equal(t, "https://docs.example.com/Annual/Report-2026.PDF", got.Asset.(*oamfile.File).URL)

	lower, err := db.CreateAsset(ctx, &oamfile.File{URL: "https://docs.example.com/annual/report-2026.pdf",
		Name: "report-2026.pdf", Type: "document"})
	assert.NoError(t, err)
	assert.NotEqual(t, ent.ID, lower.ID)
}
