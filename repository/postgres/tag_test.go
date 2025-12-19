// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"time"

	_ "github.com/mattn/go-sqlite3"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/stretchr/testify/assert"
)

func (suite *PostgresRepoTestSuite) TestUpsertAndDeleteTag() {
	t := suite.T()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tag, err := suite.db.upsertTag(ctx, string(oam.SimpleProperty), "last_monitored", "fake date", "{}")
	assert.NoError(t, err, "Failed to create tag")
	assert.Greater(t, tag, int64(0), "Tag ID is not greater than zero")

	err = suite.db.deleteTagByID(ctx, tag, true)
	assert.NoError(t, err, "Failed to delete tag")
}
