// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"strconv"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/stretchr/testify/assert"
)

func TestCreateAssetForDomainRecord(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	status := []string{"active"}
	object_id := "test object ID"
	raw_record := "test raw text"
	record_name := "test record name"
	domain := "test.com"
	punycode := "test puny code"
	extension := "com"
	created := time.Now().Add(-24 * time.Hour).UTC().Format("2006-01-02T15:04:05Z07:00")
	updated := time.Now().Add(-1 * time.Hour).UTC().Format("2006-01-02T15:04:05Z07:00")
	expiration := time.Now().Add(48 * time.Hour).UTC().Format("2006-01-02T15:04:05Z07:00")
	server := "whois.test.com"
	dr, err := db.CreateAsset(ctx, &oamreg.DomainRecord{
		Raw:            raw_record,
		ID:             object_id,
		Domain:         domain,
		Punycode:       punycode,
		Name:           record_name,
		Extension:      extension,
		WhoisServer:    server,
		CreatedDate:    created,
		UpdatedDate:    updated,
		ExpirationDate: expiration,
		Status:         status,
	})
	assert.NoError(t, err, "Failed to create asset for the DomainRecord")
	assert.NotNil(t, dr, "Entity for the DomainRecord should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, dr.CreatedAt, before, after, "DomainRecord entity CreatedAt is incorrect")
	assert.WithinRange(t, dr.LastSeen, before, after, "DomainRecord entity LastSeen is incorrect")

	id, err := strconv.ParseInt(dr.ID, 10, 64)
	assert.NoError(t, err, "DomainRecord entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "DomainRecord entity ID is not greater than zero")

	found, err := db.FindEntityById(ctx, dr.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the DomainRecord")
	assert.NotNil(t, found, "Entity found by ID for the DomainRecord should not be nil")
	assert.Equal(t, dr.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the DomainRecord does not match")
	assert.Equal(t, dr.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the DomainRecord does not match")

	dr2, ok := found.Asset.(*oamreg.DomainRecord)
	assert.True(t, ok, "Asset found by ID is not of type *oamnet.DomainRecord")
	assert.Equal(t, found.ID, dr.ID, "DomainRecord found by Entity ID does not have matching IDs")
	assert.Equal(t, dr2.Raw, raw_record, "DomainRecord found by ID does not have a matching Raw record")
	assert.Equal(t, dr2.ID, object_id, "DomainRecord found by ID does not have a matching ID")
	assert.Equal(t, dr2.Domain, domain, "DomainRecord found by ID does not have a matching Domain")
	assert.Equal(t, dr2.Punycode, punycode, "DomainRecord found by ID does not have a matching Punycode")
	assert.Equal(t, dr2.Name, record_name, "DomainRecord found by ID does not have a matching Name")
	assert.Equal(t, dr2.Extension, extension, "DomainRecord found by ID does not have a matching Extension")
	assert.Equal(t, dr2.WhoisServer, server, "DomainRecord found by ID does not have a matching WhoisServer")
	assert.Equal(t, dr2.CreatedDate, created, "DomainRecord found by ID does not have a matching CreatedDate")
	assert.Equal(t, dr2.UpdatedDate, updated, "DomainRecord found by ID does not have a matching UpdatedDate")
	assert.Equal(t, dr2.ExpirationDate, expiration, "DomainRecord found by ID does not have a matching ExpirationDate")
	assert.Equal(t, dr2.Status, status, "DomainRecord found by ID does not have a matching Status")

	err = db.DeleteEntity(ctx, dr.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the DomainRecord")

	_, err = db.FindEntityById(ctx, dr.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the DomainRecord")
}

func TestFindEntitiesByContentForDomainRecord(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	status := []string{"active"}
	object_id := "test object ID"
	raw_record := "test raw text"
	record_name := "test record name"
	domain := "test.com"
	punycode := "test puny code"
	extension := "com"
	created := time.Now().Add(-24 * time.Hour).UTC().Format("2006-01-02T15:04:05Z07:00")
	updated := time.Now().Add(-1 * time.Hour).UTC().Format("2006-01-02T15:04:05Z07:00")
	expiration := time.Now().Add(48 * time.Hour).UTC().Format("2006-01-02T15:04:05Z07:00")
	server := "whois.test.com"
	dr, err := db.CreateAsset(ctx, &oamreg.DomainRecord{
		Raw:            raw_record,
		ID:             object_id,
		Domain:         domain,
		Punycode:       punycode,
		Name:           record_name,
		Extension:      extension,
		WhoisServer:    server,
		CreatedDate:    created,
		UpdatedDate:    updated,
		ExpirationDate: expiration,
		Status:         status,
	})
	assert.NoError(t, err, "Failed to create asset for the DomainRecord")
	assert.NotNil(t, dr, "Entity for the DomainRecord should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = db.FindEntitiesByContent(ctx, oam.DomainRecord, after, 1, dbt.ContentFilters{
		"domain": domain,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	ents, err := db.FindEntitiesByContent(ctx, oam.DomainRecord, before, 1, dbt.ContentFilters{
		"domain": domain,
	})
	assert.NoError(t, err, "Failed to find entity by content for the DomainRecord")
	found := ents[0]
	assert.NotNil(t, found, "Entity found by content for the DomainRecord should not be nil")

	dr2, ok := found.Asset.(*oamreg.DomainRecord)
	assert.True(t, ok, "DomainRecord found by content is not of type *oamreg.DomainRecord")
	assert.Equal(t, found.ID, dr.ID, "DomainRecord found by content does not have matching IDs")
	assert.Equal(t, dr2.Raw, raw_record, "DomainRecord found by ID does not have a matching Raw record")
	assert.Equal(t, dr2.ID, object_id, "DomainRecord found by ID does not have a matching ID")
	assert.Equal(t, dr2.Domain, domain, "DomainRecord found by ID does not have a matching Domain")
	assert.Equal(t, dr2.Punycode, punycode, "DomainRecord found by ID does not have a matching Punycode")
	assert.Equal(t, dr2.Name, record_name, "DomainRecord found by ID does not have a matching Name")
	assert.Equal(t, dr2.Extension, extension, "DomainRecord found by ID does not have a matching Extension")
	assert.Equal(t, dr2.WhoisServer, server, "DomainRecord found by ID does not have a matching WhoisServer")
	assert.Equal(t, dr2.CreatedDate, created, "DomainRecord found by ID does not have a matching CreatedDate")
	assert.Equal(t, dr2.UpdatedDate, updated, "DomainRecord found by ID does not have a matching UpdatedDate")
	assert.Equal(t, dr2.ExpirationDate, expiration, "DomainRecord found by ID does not have a matching ExpirationDate")
	assert.Equal(t, dr2.Status, status, "DomainRecord found by ID does not have a matching Status")

	ents, err = db.FindEntitiesByContent(ctx, oam.DomainRecord, before, 0, dbt.ContentFilters{
		"name": record_name,
	})
	assert.NoError(t, err, "Failed to find entities by content for the DomainRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the DomainRecord")

	ents, err = db.FindEntitiesByContent(ctx, oam.DomainRecord, before, 0, dbt.ContentFilters{
		"extension": extension,
	})
	assert.NoError(t, err, "Failed to find entities by content for the DomainRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the DomainRecord")

	ents, err = db.FindEntitiesByContent(ctx, oam.DomainRecord, before, 0, dbt.ContentFilters{
		"punycode": punycode,
	})
	assert.NoError(t, err, "Failed to find entities by content for the DomainRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the DomainRecord")

	ents, err = db.FindEntitiesByContent(ctx, oam.DomainRecord, time.Time{}, 0, dbt.ContentFilters{
		"id": object_id,
	})
	assert.NoError(t, err, "Failed to find entities by content for the DomainRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the DomainRecord")

	ents, err = db.FindEntitiesByContent(ctx, oam.DomainRecord, before, 0, dbt.ContentFilters{
		"whois_server": server,
	})
	assert.NoError(t, err, "Failed to find entities by content for the DomainRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the DomainRecord")
}

func TestFindEntitiesByTypeForDomainRecord(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	since1 := time.Now()
	created := since1.UTC().Format("2006-01-02T15:04:05Z07:00")
	updated := created
	expiration := created
	time.Sleep(100 * time.Millisecond)

	key1 := "owasp.org"
	atype := oam.DomainRecord
	atypestr := "DomainRecord"
	ent, err := db.CreateAsset(ctx, &oamreg.DomainRecord{
		Domain:         key1,
		Punycode:       "xn--fa-hia.de",
		Name:           "OWASP",
		Extension:      "org",
		CreatedDate:    created,
		UpdatedDate:    updated,
		ExpirationDate: expiration,
		WhoisServer:    "whois.registrar.com",
	})
	assert.NoError(t, err, "Failed to create asset for the first %s", atypestr)
	assert.NotNil(t, ent, "Entity for the first %s should not be nil", atypestr)

	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()
	time.Sleep(500 * time.Millisecond)
	since23 := time.Now()
	time.Sleep(100 * time.Millisecond)

	key2 := "utica.edu"
	ent, err = db.CreateAsset(ctx, &oamreg.DomainRecord{
		Domain:         key2,
		Punycode:       "xn--privatinstruktr-jub.dk",
		Name:           "Utica University",
		Extension:      "edu",
		CreatedDate:    created,
		UpdatedDate:    updated,
		ExpirationDate: expiration,
		WhoisServer:    "whois.registrar.com",
	})
	assert.NoError(t, err, "Failed to create asset for the second %s", atypestr)
	assert.NotNil(t, ent, "Entity for the second %s should not be nil", atypestr)

	key3 := "sunypoly.edu"
	ent, err = db.CreateAsset(ctx, &oamreg.DomainRecord{
		Domain:         key3,
		Punycode:       "xn--ya-vcc.edu",
		Name:           "SUNY Polytechnic",
		Extension:      "edu",
		CreatedDate:    created,
		UpdatedDate:    updated,
		ExpirationDate: expiration,
		WhoisServer:    "whois.registrar.com",
	})
	assert.NoError(t, err, "Failed to create asset for the third %s", atypestr)
	assert.NotNil(t, ent, "Entity for the third %s should not be nil", atypestr)

	time.Sleep(100 * time.Millisecond)
	after23 := time.Now()

	for k, v := range map[string]struct {
		since    time.Time
		limit    int
		expected []string
	}{
		"find all since1": {
			since:    since1,
			limit:    3,
			expected: []string{key3, key2, key1},
		},
		"one out of all": {
			since:    since1,
			limit:    1,
			expected: []string{key3},
		},
		"two out of all": {
			since:    since1,
			limit:    2,
			expected: []string{key3, key2},
		},
		"find all after1": {
			since:    after1,
			limit:    3,
			expected: []string{key3, key2},
		},
		"one out of two and three": {
			since:    since23,
			limit:    1,
			expected: []string{key3},
		},
		"zero entities after23": {
			since:    after23,
			limit:    3,
			expected: []string{},
		},
		"no since returns error": {
			since:    time.Time{},
			limit:    0,
			expected: []string{},
		},
	} {
		ents, err := db.FindEntitiesByType(ctx, atype, v.since, v.limit)

		var got []string
		for _, ent := range ents {
			got = append(got, ent.Asset.Key())
		}

		if len(v.expected) > 0 {
			assert.NoError(t, err, "The %s test failed for %s: expected %v: got: %v", k, atypestr, v.expected, got)
		} else {
			assert.Error(t, err, "The %s test failed for %s: zero findings should return an error", k, atypestr)
		}

		assert.Len(t, ents, len(v.expected),
			"The %s test expected to find exactly %d entities for %s: got: %d", k, v.limit, atypestr, len(ents),
		)
	}
}
