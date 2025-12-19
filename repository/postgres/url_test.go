// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"strconv"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamurl "github.com/owasp-amass/open-asset-model/url"
	"github.com/stretchr/testify/assert"
)

func (suite *PostgresRepoTestSuite) TestCreateAssetForURL() {
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

func (suite *PostgresRepoTestSuite) TestFindEntitiesByContentForURL() {
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

	_, err = suite.db.FindOneEntityByContent(ctx, oam.URL, after, dbt.ContentFilters{
		"url": raw,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	found, err := suite.db.FindOneEntityByContent(ctx, oam.URL, before, dbt.ContentFilters{
		"url": raw,
	})
	assert.NoError(t, err, "Failed to find entity by content for the URL")
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
		ents, err := suite.db.FindEntitiesByContent(ctx, oam.URL, before, dbt.ContentFilters{k: v})
		assert.NoError(t, err, "Failed to find entities by content for the URL")
		assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the URL")
	}
}
