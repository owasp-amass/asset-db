// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlrepo"
	"github.com/stretchr/testify/assert"
)

func TestCacheImplementsRepository(t *testing.T) {
	var _ repository.Repository = &Cache{}      // Verify proper implementation of the Repository interface
	var _ repository.Repository = (*Cache)(nil) // Verify *Cache properly implements the  Repository interface.
}

func TestStartTime(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		db1.Close()
		db2.Close()
		os.RemoveAll(dir)
	}()

	t1 := time.Now()
	time.Sleep(250 * time.Millisecond)
	cache, err := New(db1, db2)
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

func TestGetDBType(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		db1.Close()
		db2.Close()
		os.RemoveAll(dir)
	}()

	cache, err := New(db1, db2)
	assert.NoError(t, err)
	defer cache.Close()

	if dbtype := cache.GetDBType(); dbtype != sqlrepo.SQLite {
		t.Errorf("DB type was: %s, expected: %s", dbtype, sqlrepo.SQLite)
	}
}

func createTestRepositories() (repository.Repository, repository.Repository, string, error) {
	dir, err := os.MkdirTemp("", fmt.Sprintf("test-%d", rand.Intn(100)))
	if err != nil {
		return nil, nil, "", errors.New("failed to create the temp dir")
	}

	c := assetdb.New(sqlrepo.SQLite, filepath.Join(dir, "cache.sqlite"))
	if c == nil {
		return nil, nil, "", errors.New("failed to create the cache db")
	}

	db := assetdb.New(sqlrepo.SQLite, filepath.Join(dir, "assetdb.sqlite"))
	if db == nil {
		return nil, nil, "", errors.New("failed to create the database")
	}

	return c.Repo, db.Repo, dir, nil
}
