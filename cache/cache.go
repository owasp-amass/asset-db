// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"time"

	"github.com/owasp-amass/asset-db/repository"
)

type Cache struct {
	start time.Time
	freq  time.Duration
	cache repository.Repository
	db    repository.Repository
}

func New(cache, database repository.Repository, freq time.Duration) (*Cache, error) {
	return &Cache{
		start: time.Now(),
		freq:  freq,
		cache: cache,
		db:    database,
	}, nil
}

// StartTime returns the time that the cache was created.
func (c *Cache) StartTime() time.Time {
	return c.start
}

// Close implements the Repository interface.
func (c *Cache) Close() error {
	return c.cache.Close()
}

// GetDBType implements the Repository interface.
func (c *Cache) GetDBType() string {
	return c.db.GetDBType()
}
