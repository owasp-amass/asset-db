// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"log"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/repository/postgres/testhelpers"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamurl "github.com/owasp-amass/open-asset-model/url"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PostgresURLTestSuite struct {
	suite.Suite
	container *testhelpers.PostgresContainer
	db        *PostgresRepository
}

func TestPostgresURLTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresURLTestSuite))
}

func (suite *PostgresURLTestSuite) SetupSuite() {
	var err error
	suite.container, suite.db, err = setupContainerAndPostgresRepo()
	if err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresURLTestSuite) TearDownSuite() {
	if err := suite.container.Terminate(context.Background()); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func (suite *PostgresURLTestSuite) TestCreateAssetForURL() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	// URL with username and password, options, and fragment
	raw := "http://username:password@www.fake-domain.com:8080/path?query=param#fragment"
	scheme := "http"
	username := "username"
	password := "password"
	host := "www.fake-domain.com"
	port := 8080
	path := "/path"
	options := "query=param"
	fragment := "fragment"

	url, err := suite.db.CreateAsset(ctx, &oamurl.URL{
		Raw:      raw,
		Scheme:   scheme,
		Username: username,
		Password: password,
		Host:     host,
		Port:     port,
		Path:     path,
		Options:  options,
		Fragment: fragment,
	})
	assert.NoError(t, err, "Failed to create asset for the URL")
	assert.NotNil(t, url, "Entity for the URL should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, url.CreatedAt, before, after, "URL entity CreatedAt is incorrect")
	assert.WithinRange(t, url.LastSeen, before, after, "URL entity LastSeen is incorrect")

	id, err := strconv.ParseInt(url.ID, 10, 64)
	assert.NoError(t, err, "URL entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "URL entity ID is not greater than zero")

	found, err := suite.db.FindEntityById(ctx, url.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the URL")
	assert.NotNil(t, found, "Entity found by ID for the URL should not be nil")
	assert.Equal(t, url.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the URL does not match")
	assert.Equal(t, url.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the URL does not match")

	url2, ok := found.Asset.(*oamurl.URL)
	assert.True(t, ok, "URL found by ID is not of type *oamurl.URL")
	assert.Equal(t, found.ID, url.ID, "URL found by content does not have matching IDs")
	assert.Equal(t, url2.Raw, raw, "URL found by content does not have matching raw URL")
	assert.Equal(t, url2.Scheme, scheme, "URL found by content does not have matching scheme")
	assert.Equal(t, url2.Username, username, "URL found by content does not have matching username")
	assert.Equal(t, url2.Password, password, "URL found by content does not have matching password")
	assert.Equal(t, url2.Host, host, "URL found by content does not have matching host")
	assert.Equal(t, url2.Port, port, "URL found by content does not have matching port")
	assert.Equal(t, url2.Path, path, "URL found by content does not have matching path")
	assert.Equal(t, url2.Options, options, "URL found by content does not have matching options")
	assert.Equal(t, url2.Fragment, fragment, "URL found by content does not have matching fragment")

	err = suite.db.DeleteEntity(ctx, url.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the URL")

	_, err = suite.db.FindEntityById(ctx, url.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the URL")
}

func (suite *PostgresURLTestSuite) TestFindEntitiesByContentForURL() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	// URL with username and password, options, and fragment
	raw := "http://username:password@www.fake-domain.com:8080/path?query=param#fragment"
	scheme := "http"
	username := "username"
	password := "password"
	host := "www.fake-domain.com"
	port := 8080
	path := "/path"
	options := "query=param"
	fragment := "fragment"

	url, err := suite.db.CreateAsset(ctx, &oamurl.URL{
		Raw:      raw,
		Scheme:   scheme,
		Username: username,
		Password: password,
		Host:     host,
		Port:     port,
		Path:     path,
		Options:  options,
		Fragment: fragment,
	})
	assert.NoError(t, err, "Failed to create asset for the URL")
	assert.NotNil(t, url, "Entity for the URL should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = suite.db.FindEntitiesByContent(ctx, oam.URL, after, 1, dbt.ContentFilters{
		"url": raw,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.URL, before, 1, dbt.ContentFilters{
		"url": raw,
	})
	assert.NoError(t, err, "Failed to find entity by content for the URL")
	found := ents[0]
	assert.NotNil(t, found, "Entity found by content for the URL should not be nil")

	url2, ok := found.Asset.(*oamurl.URL)
	assert.True(t, ok, "URL found by content is not of type *oamurl.URL")
	assert.Equal(t, found.ID, url.ID, "URL found by content does not have matching IDs")
	assert.Equal(t, url2.Raw, raw, "URL found by content does not have matching raw URL")
	assert.Equal(t, url2.Scheme, scheme, "URL found by content does not have matching scheme")
	assert.Equal(t, url2.Username, username, "URL found by content does not have matching username")
	assert.Equal(t, url2.Password, password, "URL found by content does not have matching password")
	assert.Equal(t, url2.Host, host, "URL found by content does not have matching host")
	assert.Equal(t, url2.Port, port, "URL found by content does not have matching port")
	assert.Equal(t, url2.Path, path, "URL found by content does not have matching path")
	assert.Equal(t, url2.Options, options, "URL found by content does not have matching options")
	assert.Equal(t, url2.Fragment, fragment, "URL found by content does not have matching fragment")

	for k, v := range map[string]string{
		"url":    raw,
		"scheme": scheme,
	} {
		ents, err := suite.db.FindEntitiesByContent(ctx, oam.URL, before, 0, dbt.ContentFilters{k: v})
		assert.NoError(t, err, "Failed to find entities by content for the URL")
		assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the URL")
	}
}

func (suite *PostgresURLTestSuite) TestFindEntitiesByTypeForURL() {
	t := suite.T()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	since1 := time.Now()
	time.Sleep(100 * time.Millisecond)

	atype := oam.URL
	atypestr := "URL"
	key1 := "https://fake1.net"
	url, err := url.Parse(key1)
	assert.NoError(t, err, "Failed to parse the first URL")
	ent, err := suite.db.CreateAsset(ctx, &oamurl.URL{
		Raw:    key1,
		Scheme: url.Scheme,
		Host:   url.Host,
	})
	assert.NoError(t, err, "Failed to create asset for the first %s", atypestr)
	assert.NotNil(t, ent, "Entity for the first %s should not be nil", atypestr)

	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()
	time.Sleep(500 * time.Millisecond)
	since23 := time.Now()
	time.Sleep(100 * time.Millisecond)

	key2 := "https://fake2.net"
	url, err = url.Parse(key2)
	assert.NoError(t, err, "Failed to parse the second URL")
	ent, err = suite.db.CreateAsset(ctx, &oamurl.URL{
		Raw:    key2,
		Scheme: url.Scheme,
		Host:   url.Host,
	})
	assert.NoError(t, err, "Failed to create asset for the second %s", atypestr)
	assert.NotNil(t, ent, "Entity for the second %s should not be nil", atypestr)

	key3 := "https://fake3.net"
	url, err = url.Parse(key3)
	assert.NoError(t, err, "Failed to parse the third URL")
	ent, err = suite.db.CreateAsset(ctx, &oamurl.URL{
		Raw:    key3,
		Scheme: url.Scheme,
		Host:   url.Host,
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
		ents, err := suite.db.FindEntitiesByType(ctx, atype, v.since, v.limit)

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
