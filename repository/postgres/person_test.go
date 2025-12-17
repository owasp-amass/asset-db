// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

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
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

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
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

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

	_, err = db.FindOneEntityByContent(ctx, oam.Person, after, dbt.ContentFilters{
		"unique_id": uniqueID,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	found, err := db.FindOneEntityByContent(ctx, oam.Person, before, dbt.ContentFilters{
		"unique_id": uniqueID,
	})
	assert.NoError(t, err, "Failed to find entity by content for the Person")
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
		ents, err := db.FindEntitiesByContent(ctx, oam.Person, before, dbt.ContentFilters{k: v})
		assert.NoError(t, err, "Failed to find entities by content for the Person")
		assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the Person")
	}
}
