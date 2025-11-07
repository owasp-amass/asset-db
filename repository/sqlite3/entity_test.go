// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"fmt"
	"testing"

	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/stretchr/testify/assert"
)

func BenchmarkCreateAsset(b *testing.B) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(b, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(b, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	var i int64
	for b.Loop() {
		_, _ = db.CreateAsset(context.Background(), &oamdns.FQDN{Name: fmt.Sprintf("www%d.example.com", i)})
		i++
	}
}
