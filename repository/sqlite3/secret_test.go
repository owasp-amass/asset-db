// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"testing"

	"github.com/owasp-amass/asset-db/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Secrets are stored as given, replaced by name, listed by name and
// deleted; one that is not encrypted is refused.
func TestSQLiteSecrets(t *testing.T) {
	db, dir, err := setupTempSQLite()
	require.NoError(t, err, "creating the database")
	defer teardownTempSQLite(db, dir)
	ctx := context.Background()

	_, err = db.PutSecret(ctx, &types.Secret{Name: "Shodan/apikey", Ciphertext: []byte("x")})
	assert.Error(t, err, "a secret without a nonce and key ID is refused")

	put, err := db.PutSecret(ctx, &types.Secret{Name: "Shodan/apikey", Ciphertext: []byte{1, 2, 3},
		Nonce: []byte{9, 9}, KeyID: "k1", UpdatedBy: "jeff"})
	require.NoError(t, err, "storing a secret")
	assert.False(t, put.UpdatedAt.IsZero(), "a stored secret has an update time")

	_, err = db.PutSecret(ctx, &types.Secret{Name: "Censys/apikey", Ciphertext: []byte{4}, Nonce: []byte{8},
		KeyID: "k1"})
	require.NoError(t, err)
	_, err = db.PutSecret(ctx, &types.Secret{Name: "Shodan/apikey", Ciphertext: []byte{5, 6}, Nonce: []byte{7},
		KeyID: "k2", UpdatedBy: "rotate"})
	require.NoError(t, err, "replacing a secret")

	got, err := db.GetSecret(ctx, "Shodan/apikey")
	require.NoError(t, err, "reading a secret")
	assert.Equal(t, []byte{5, 6}, got.Ciphertext, "the newest ciphertext is kept")
	assert.Equal(t, []byte{7}, got.Nonce)
	assert.Equal(t, "k2", got.KeyID)
	assert.Equal(t, "rotate", got.UpdatedBy)

	all, err := db.ListSecrets(ctx)
	require.NoError(t, err)
	if assert.Len(t, all, 2) {
		assert.Equal(t, "Censys/apikey", all[0].Name, "secrets are listed by name")
	}

	require.NoError(t, db.DeleteSecret(ctx, "Shodan/apikey"))
	_, err = db.GetSecret(ctx, "Shodan/apikey")
	assert.Error(t, err, "a deleted secret is gone")
	require.NoError(t, db.DeleteSecret(ctx, "Shodan/apikey"), "deleting a missing secret does nothing")
}
