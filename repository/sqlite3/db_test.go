// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"os"
	"path/filepath"
)

func setupTempSQLite() (*SqliteRepository, string, error) {
	dir, err := os.MkdirTemp("", "sqlite-test-")
	if err != nil {
		return nil, "", err
	}

	fpath := filepath.Join(dir, "db.sqlite")
	repo, err := New(SQLite, fpath)
	return repo, fpath, err
}

func teardownTempSQLite(repo *SqliteRepository, dir string) {
	if repo != nil {
		_ = repo.Close()
	}
	_ = os.RemoveAll(dir)
}
