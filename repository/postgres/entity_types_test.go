// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"testing"

	oam "github.com/owasp-amass/open-asset-model"
	"github.com/stretchr/testify/assert"
)

func TestEntityTypesCache(t *testing.T) {
	c := newEntityTypes()
	for i, at := range oam.AssetList {
		c.put(int64(i), normalizeType(string(at)))
	}
	for i, at := range oam.AssetList {
		got, ok := c.get(int64(i))
		assert.True(t, ok, "every OAM asset type can be cached")
		assert.Equal(t, normalizeType(string(at)), got, "the cached type is the stored one")
	}

	c.put(1000, "notatype")
	_, ok := c.get(1000)
	assert.False(t, ok, "an unknown type name is not cached")

	c.forget(0)
	_, ok = c.get(0)
	assert.False(t, ok, "a forgotten entity is not cached")

	for i := range maxCachedEntityTypes + 1 {
		c.put(int64(i), "fqdn")
	}
	assert.LessOrEqual(t, len(c.m), maxCachedEntityTypes, "the cache never grows past its bound")

	var empty *entityTypes
	empty.put(1, "fqdn")
	_, ok = empty.get(1)
	assert.False(t, ok, "a nil cache stores nothing")
}
