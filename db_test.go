// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assetdb

import (
	"testing"

	"github.com/owasp-amass/asset-db/repository/sqlrepo"
)

func TestNew(t *testing.T) {
	if _, err := New(sqlrepo.SQLiteMemory, ""); err != nil {
		t.Errorf("Failed to create a new SQLite in-memory repository: %v", err)
	}
}
