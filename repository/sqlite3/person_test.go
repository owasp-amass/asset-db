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
	"github.com/owasp-amass/open-asset-model/people"
	"github.com/stretchr/testify/assert"
)

func TestCreateAssetForPerson(t *testing.T) {
	db, dir, err := setupTempSQLite()
	assert.NoError(t, err, "Failed to create the sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer teardownTempSQLite(db, dir)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	uniqueID := "fake unique id"
	fullName := "Fake Full Name"
	firstName := "Fake First Name"
	middleName := "Fake Middle Name"
	familyName := "Fake Family Name"
	birthdate := time.Date(2020, time.January, 15, 0, 0, 0, 0, time.UTC).Format("2006-01-02T15:04:05Z07:00")
	gender := "Unknown"

	person, err := db.CreateAsset(ctx, &people.Person{
		ID:         uniqueID,
		FullName:   fullName,
		FirstName:  firstName,
		MiddleName: middleName,
		FamilyName: familyName,
		BirthDate:  birthdate,
		Gender:     gender,
	})
	assert.NoError(t, err, "Failed to create asset for the Person")
	assert.NotNil(t, person, "Entity for the Person should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, person.CreatedAt, before, after, "Person entity CreatedAt is incorrect")
	assert.WithinRange(t, person.LastSeen, before, after, "Person entity LastSeen is incorrect")

	id, err := strconv.ParseInt(person.ID, 10, 64)
	assert.NoError(t, err, "Person entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "Person entity ID is not greater than zero")

	found, err := db.FindEntityById(ctx, person.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the Person")
	assert.NotNil(t, found, "Entity found by ID for the Person should not be nil")
	assert.Equal(t, person.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the Person does not match")
	assert.Equal(t, person.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the Person does not match")

	person2, ok := found.Asset.(*people.Person)
	assert.True(t, ok, "Person found by ID is not of type *people.Person")
	assert.Equal(t, found.ID, person.ID, "Person found by Entity ID does not have matching IDs")
	assert.Equal(t, person2.ID, uniqueID, "Person found by ID does not have matching UniqueID")
	assert.Equal(t, person2.FullName, fullName, "Person found by ID does not have matching FullName")
	assert.Equal(t, person2.FirstName, firstName, "Person found by ID does not have matching FirstName")
	assert.Equal(t, person2.MiddleName, middleName, "Person found by ID does not have matching MiddleName")
	assert.Equal(t, person2.FamilyName, familyName, "Person found by ID does not have matching FamilyName")
	assert.Equal(t, person2.BirthDate, birthdate, "Person found by ID does not have matching BirthDate")
	assert.Equal(t, person2.Gender, gender, "Person found by ID does not have matching Gender")

	err = db.DeleteEntity(ctx, person.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the Person")

	_, err = db.FindEntityById(ctx, person.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the Person")
}

func TestFindEntitiesByContentForPerson(t *testing.T) {
	db, dir, err := setupTempSQLite()
	assert.NoError(t, err, "Failed to create the sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer teardownTempSQLite(db, dir)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	uniqueID := "fake unique id"
	fullName := "Fake Full Name"
	firstName := "Fake First Name"
	middleName := "Fake Middle Name"
	familyName := "Fake Family Name"
	birthdate := time.Date(2020, time.January, 15, 0, 0, 0, 0, time.UTC).Format("2006-01-02")
	gender := "Unknown"

	person, err := db.CreateAsset(ctx, &people.Person{
		ID:         uniqueID,
		FullName:   fullName,
		FirstName:  firstName,
		MiddleName: middleName,
		FamilyName: familyName,
		BirthDate:  birthdate,
		Gender:     gender,
	})
	assert.NoError(t, err, "Failed to create asset for the Person")
	assert.NotNil(t, person, "Entity for the Person should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = db.FindEntitiesByContent(ctx, oam.Person, after, 1, dbt.ContentFilters{
		"unique_id": uniqueID,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	ents, err := db.FindEntitiesByContent(ctx, oam.Person, before, 1, dbt.ContentFilters{
		"unique_id": uniqueID,
	})
	assert.NoError(t, err, "Failed to find entity by content for the Person")
	found := ents[0]
	assert.NotNil(t, found, "Entity found by content for the Person should not be nil")

	person2, ok := found.Asset.(*people.Person)
	assert.True(t, ok, "Person found by content is not of type *people.Person")
	assert.Equal(t, found.ID, person.ID, "Person found by content does not have matching IDs")
	assert.Equal(t, person2.ID, uniqueID, "Person found by content does not have matching unique ID")
	assert.Equal(t, person2.FullName, fullName, "Person found by content does not have matching full name")
	assert.Equal(t, person2.FirstName, firstName, "Person found by content does not have matching first name")
	assert.Equal(t, person2.MiddleName, middleName, "Person found by content does not have matching middle name")
	assert.Equal(t, person2.FamilyName, familyName, "Person found by content does not have matching family name")
	assert.Equal(t, person2.BirthDate, birthdate, "Person found by content does not have matching birthdate")
	assert.Equal(t, person2.Gender, gender, "Person found by content does not have matching gender")

	for k, v := range map[string]string{
		"unique_id":   uniqueID,
		"full_name":   fullName,
		"first_name":  firstName,
		"family_name": familyName,
	} {
		ents, err := db.FindEntitiesByContent(ctx, oam.Person, before, 0, dbt.ContentFilters{k: v})
		assert.NoError(t, err, "Failed to find entities by content for the Person")
		assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the Person")
	}
}

func TestFindEntitiesByTypeForPerson(t *testing.T) {
	db, dir, err := setupTempSQLite()
	assert.NoError(t, err, "Failed to create the sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer teardownTempSQLite(db, dir)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	since1 := time.Now()
	time.Sleep(100 * time.Millisecond)

	key1 := "Fake1"
	atype := oam.Person
	atypestr := "Person"
	ent, err := db.CreateAsset(ctx, &people.Person{
		ID:       key1,
		FullName: "fake name 1",
	})
	assert.NoError(t, err, "Failed to create asset for the first %s", atypestr)
	assert.NotNil(t, ent, "Entity for the first %s should not be nil", atypestr)

	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()
	time.Sleep(500 * time.Millisecond)
	since23 := time.Now()
	time.Sleep(100 * time.Millisecond)

	key2 := "Fake2"
	ent, err = db.CreateAsset(ctx, &people.Person{
		ID:       key2,
		FullName: "fake name 2",
	})
	assert.NoError(t, err, "Failed to create asset for the second %s", atypestr)
	assert.NotNil(t, ent, "Entity for the second %s should not be nil", atypestr)

	key3 := "Fake3"
	ent, err = db.CreateAsset(ctx, &people.Person{
		ID:       key3,
		FullName: "fake name 3",
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
