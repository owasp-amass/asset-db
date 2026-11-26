// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Work is claimed oldest first by one owner at a time, acked, released,
// renewed and reclaimed when its lease expires; enqueuing it again returns
// it to queued in its place.
func TestPostgresWorkQueue(t *testing.T) {
	db := valueFinderRepo(t)
	ctx := context.Background()
	const q, fqdn = "job-1", "FQDN"
	// a database kept between runs starts without them
	require.NoError(t, db.DeleteQueue(ctx, q))
	require.NoError(t, db.DeleteQueue(ctx, "job-2"))

	require.NoError(t, db.EnqueueWork(ctx, q, fqdn, "a", "b", "c", "a"), "enqueuing")
	assert.Error(t, db.EnqueueWork(ctx, q, fqdn, ""), "an empty key is refused")
	require.NoError(t, db.EnqueueWork(ctx, "job-2", fqdn, "a"), "another queue")

	has, err := db.HasWork(ctx, q, "a", "c", "z")
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"a": true, "c": true}, has, "the keys in the queue")

	_, err = db.ClaimWork(ctx, q, fqdn, "", 1, time.Hour)
	assert.Error(t, err, "a claim names its owner")
	got, err := db.ClaimWork(ctx, q, fqdn, "w1", 2, time.Hour)
	require.NoError(t, err, "claiming")
	assert.Equal(t, []string{"a", "b"}, got, "the oldest items")
	got, err = db.ClaimWork(ctx, q, fqdn, "w2", 5, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, []string{"c"}, got, "a second owner gets what is left")
	got, err = db.ClaimWork(ctx, q, fqdn, "w2", 5, time.Hour)
	require.NoError(t, err)
	assert.Empty(t, got, "nothing is claimed twice")

	c, err := db.CountWork(ctx, q, fqdn)
	require.NoError(t, err)
	assert.Equal(t, types.WorkCounts{Leased: 3}, c)

	assert.ErrorIs(t, db.AckWork(ctx, q, "a", "w2"), types.ErrWorkNotLeased, "only the owner acks")
	require.NoError(t, db.AckWork(ctx, q, "a", "w1"), "acking")
	require.NoError(t, db.ReleaseWork(ctx, q, "b", "w2"), "another owner's release does nothing")
	require.NoError(t, db.ReleaseWork(ctx, q, "b", "w1"), "releasing")
	c, err = db.CountWork(ctx, q, fqdn)
	require.NoError(t, err)
	assert.Equal(t, types.WorkCounts{Queued: 1, Leased: 1, Done: 1}, c)

	got, err = db.ClaimWork(ctx, q, fqdn, "w2", 5, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, []string{"b"}, got, "a released item is claimed again")
	n, err := db.RenewWork(ctx, q, "w2", time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n, "renewing every lease the owner holds")

	// an expired lease is counted as queued and claimed by another owner
	require.NoError(t, db.EnqueueWork(ctx, q, "IPAddress", "d"))
	_, err = db.ClaimWork(ctx, q, "IPAddress", "w1", 1, 20*time.Millisecond)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	c, err = db.CountWork(ctx, q, "IPAddress")
	require.NoError(t, err)
	assert.Equal(t, types.WorkCounts{Queued: 1}, c, "an expired lease counts as queued")
	got, err = db.ClaimWork(ctx, q, "IPAddress", "w2", 1, 0)
	require.NoError(t, err)
	assert.Equal(t, []string{"d"}, got, "an expired lease is claimed again")
	time.Sleep(50 * time.Millisecond)
	got, err = db.ClaimWork(ctx, q, "IPAddress", "w1", 1, time.Hour)
	require.NoError(t, err)
	assert.Empty(t, got, "a lease without an end does not expire")

	// enqueuing a done item queues it again, in its first place
	require.NoError(t, db.EnqueueWork(ctx, q, fqdn, "e", "a"))
	got, err = db.ClaimWork(ctx, q, fqdn, "w3", 5, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "e"}, got, "the item keeps its place")

	c, err = db.CountWork(ctx, q, "")
	require.NoError(t, err)
	assert.Equal(t, types.WorkCounts{Leased: 5}, c, "every kind")

	require.NoError(t, db.DeleteQueue(ctx, q), "deleting the queue")
	c, err = db.CountWork(ctx, q, "")
	require.NoError(t, err)
	assert.Equal(t, types.WorkCounts{}, c, "the queue is gone")
	c, err = db.CountWork(ctx, "job-2", "")
	require.NoError(t, err)
	assert.Equal(t, types.WorkCounts{Queued: 1}, c, "other queues are kept")
}
