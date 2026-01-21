// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/stretchr/testify/assert"
)

func TestUpsertAndDeleteTag(t *testing.T) {
	db, err := New(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tag, err := db.upsertTag(ctx, string(oam.SimpleProperty), "last_monitored", "fake date", "{}")
	assert.NoError(t, err, "Failed to create tag")
	assert.Greater(t, tag, int64(0), "Tag ID is not greater than zero")

	err = db.deleteTagByID(ctx, tag, true)
	assert.NoError(t, err, "Failed to delete tag")
}
