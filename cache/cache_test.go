// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"errors"
	"fmt"
	"testing"
	"time"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlrepo"
	"github.com/stretchr/testify/assert"
)

func TestStartTime(t *testing.T) {
	c, db, err := createTestRepositories()
	assert.NoError(t, err)
	defer c.Close()
	defer db.Close()

	t1 := time.Now()
	time.Sleep(250 * time.Millisecond)
	cache, err := New(c, db)
	assert.NoError(t, err)
	defer cache.Close()
	time.Sleep(250 * time.Millisecond)
	t2 := time.Now()

	if start := cache.StartTime(); start.UnixNano() <= t1.UnixNano() {
		t.Errorf("cache start time: %s, t1 time: %s", start.Format(time.RFC3339Nano), t1.Format(time.RFC3339Nano))
	} else if t2.UnixNano() <= start.UnixNano() {
		t.Errorf("cache start time: %s, t2 time: %s", start.Format(time.RFC3339Nano), t2.Format(time.RFC3339Nano))
	}
}

func createTestRepositories() (repository.Repository, repository.Repository, error) {
	cache := assetdb.New(sqlrepo.SQLiteMemory, "")
	if cache == nil {
		return nil, nil, errors.New("failed to create the cache db")
	}

	dsn := fmt.Sprintf("host=localhost port=5432 user=%s password=%s dbname=%s", "postgres", "postgres", "postgres")
	db, err := repository.New(sqlrepo.Postgres, dsn)
	if err != nil || db == nil {
		return nil, nil, errors.New("failed to create the database")
	}

	return cache.Repo, db, nil
}
