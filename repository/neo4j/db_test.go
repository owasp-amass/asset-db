//go:build integration

// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"fmt"
	"os"
	"testing"

	neomigrations "github.com/owasp-amass/asset-db/migrations/neo4j"
	"github.com/stretchr/testify/assert"
)

var store *neoRepository

func TestMain(m *testing.M) {
	dsn := "bolt://neo4j:hackme4fun@localhost:7687/amass"

	store, err := New("neo4j", dsn)
	if err != nil {
		fmt.Println(err)
		return
	}

	if err := neomigrations.InitializeSchema(store.db, store.dbname); err != nil {
		fmt.Println(err)
		return
	}

	os.Exit(m.Run())
}

func TestClose(t *testing.T) {
	err := store.Close()
	assert.NoError(t, err)
}

func TestGetDBType(t *testing.T) {
	if db := store.GetDBType(); db != Neo4j {
		t.Errorf("Failed to return the correct database type")
	}
}
