// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The journal keeps records in the order they were appended, by topic, and
// returns a key's latest; data and causes are kept.
func TestPostgresJournal(t *testing.T) {
	db := valueFinderRepo(t)
	var err error
	ctx := context.Background()

	_, err = db.AppendJournal(ctx, &types.JournalRecord{Topic: "review"})
	assert.Error(t, err, "a record has a kind")
	_, err = db.AppendJournal(ctx, &types.JournalRecord{Topic: "review", Kind: "x", Data: json.RawMessage("{")})
	assert.Error(t, err, "a record's data is JSON")

	first, err := db.AppendJournal(ctx, &types.JournalRecord{Topic: "review", Kind: "proposal", Key: "own-1",
		Data: json.RawMessage(`{"status":"pending"}`), Actor: "amass@host-a"})
	require.NoError(t, err, "appending a record")
	assert.Positive(t, first.Seq, "an appended record has a sequence number")
	assert.False(t, first.At.IsZero(), "an appended record has a time")

	_, err = db.AppendJournal(ctx, &types.JournalRecord{Topic: "runs", Kind: "run", Key: "r-1"})
	require.NoError(t, err, "appending to another topic")
	second, err := db.AppendJournal(ctx, &types.JournalRecord{Topic: "review", Kind: "outcome", Key: "own-1",
		Data: json.RawMessage(`{"status":"applied"}`), Cause: first.Seq})
	require.NoError(t, err, "appending a caused record")
	assert.Greater(t, second.Seq, first.Seq, "later records have higher numbers")

	recs, err := db.ReadJournal(ctx, "review", 0, 0)
	require.NoError(t, err, "reading a topic")
	if assert.Len(t, recs, 2, "only the topic's records are read") {
		assert.Equal(t, first.Seq, recs[0].Seq, "records are in order")
		assert.Equal(t, "own-1", recs[0].Key, "the key is kept")
		assert.Equal(t, "amass@host-a", recs[0].Actor, "the actor is kept")
		assert.JSONEq(t, `{"status":"pending"}`, string(recs[0].Data), "the data is kept")
		assert.Equal(t, first.Seq, recs[1].Cause, "the cause is kept")
	}

	recs, err = db.ReadJournal(ctx, "review", first.Seq, 0)
	require.NoError(t, err, "reading after a record")
	if assert.Len(t, recs, 1, "only the records after it are read") {
		assert.Equal(t, second.Seq, recs[0].Seq)
	}
	recs, err = db.ReadJournal(ctx, "review", 0, 1)
	require.NoError(t, err, "reading at most one")
	assert.Len(t, recs, 1, "the limit holds")

	latest, err := db.LatestJournal(ctx, "review", "own-1")
	require.NoError(t, err, "finding a key's latest record")
	assert.Equal(t, "outcome", latest.Kind, "the newest record is the latest")
	_, err = db.LatestJournal(ctx, "review", "own-2")
	assert.Error(t, err, "a key with no records has no latest")

	runs, err := db.ReadJournal(ctx, "runs", 0, 0)
	require.NoError(t, err)
	if assert.Len(t, runs, 1) {
		assert.JSONEq(t, `{}`, string(runs[0].Data), "a record without data holds {}")
	}

	// filtered reads: by key, by kinds, by both after a record
	third, err := db.AppendJournal(ctx, &types.JournalRecord{Topic: "review", Kind: "proposal", Key: "own-3"})
	require.NoError(t, err)
	recs, err = db.ReadJournalFiltered(ctx, "review", types.JournalFilter{Key: "own-1"}, 0, 0)
	require.NoError(t, err, "reading a key's records")
	assert.Len(t, recs, 2, "only the key's records are read")
	recs, err = db.ReadJournalFiltered(ctx, "review", types.JournalFilter{Kinds: []string{"proposal"}}, 0, 0)
	require.NoError(t, err, "reading a kind's records")
	if assert.Len(t, recs, 2, "only the kind's records are read") {
		assert.Equal(t, first.Seq, recs[0].Seq, "records are in order")
		assert.Equal(t, third.Seq, recs[1].Seq)
	}
	recs, err = db.ReadJournalFiltered(ctx, "review", types.JournalFilter{Key: "own-1",
		Kinds: []string{"outcome", "proposal"}}, first.Seq, 0)
	require.NoError(t, err, "reading a key's kinds after a record")
	if assert.Len(t, recs, 1, "only the key's later records of the kinds are read") {
		assert.Equal(t, second.Seq, recs[0].Seq)
	}
	recs, err = db.ReadJournalFiltered(ctx, "review", types.JournalFilter{Kinds: []string{"proposal"}}, 0, 1)
	require.NoError(t, err)
	assert.Len(t, recs, 1, "the limit holds for a filtered read")
	recs, err = db.ReadJournalFiltered(ctx, "runs", types.JournalFilter{Kinds: []string{"proposal"}}, 0, 0)
	require.NoError(t, err)
	assert.Empty(t, recs, "another topic's records are not read")
}

// A lease has one holder at a time; its holder renews it, and anyone takes
// it once it is released or expired.
func TestPostgresLeases(t *testing.T) {
	db := valueFinderRepo(t)
	var err error
	ctx := context.Background()

	_, _, err = db.AcquireLease(ctx, "", "a", time.Minute, nil)
	assert.Error(t, err, "a lease has a name")
	_, _, err = db.AcquireLease(ctx, "doc:1", "a", 0, nil)
	assert.Error(t, err, "a lease lasts a positive time")

	l, ok, err := db.AcquireLease(ctx, "doc:1", "engine-a", time.Minute, json.RawMessage(`{"run":"r-1"}`))
	require.NoError(t, err, "acquiring a free lease")
	assert.True(t, ok, "a free lease is acquired")
	assert.Equal(t, "engine-a", l.Holder)
	assert.JSONEq(t, `{"run":"r-1"}`, string(l.Data), "the lease's data is kept")

	l, ok, err = db.AcquireLease(ctx, "doc:1", "engine-b", time.Minute, nil)
	require.NoError(t, err, "asking for a held lease")
	assert.False(t, ok, "a held lease is not acquired")
	assert.Equal(t, "engine-a", l.Holder, "the holder is reported")

	renewed, ok, err := db.AcquireLease(ctx, "doc:1", "engine-a", time.Hour, nil)
	require.NoError(t, err, "renewing")
	assert.True(t, ok, "the holder renews its lease")
	assert.True(t, renewed.ExpiresAt.After(time.Now().Add(30*time.Minute)), "a renewal extends the lease")

	require.NoError(t, db.ReleaseLease(ctx, "doc:1", "engine-b"), "releasing a lease one does not hold")
	found, err := db.FindLease(ctx, "doc:1")
	require.NoError(t, err, "finding a live lease")
	assert.Equal(t, "engine-a", found.Holder, "only its holder releases a lease")

	require.NoError(t, db.ReleaseLease(ctx, "doc:1", "engine-a"), "releasing")
	_, err = db.FindLease(ctx, "doc:1")
	assert.Error(t, err, "a released lease is gone")
	_, ok, err = db.AcquireLease(ctx, "doc:1", "engine-b", time.Minute, nil)
	require.NoError(t, err)
	assert.True(t, ok, "a released lease is acquired by another")

	_, ok, err = db.AcquireLease(ctx, "watch:1", "engine-a", 50*time.Millisecond, nil)
	require.NoError(t, err)
	require.True(t, ok)
	time.Sleep(1100 * time.Millisecond)
	_, err = db.FindLease(ctx, "watch:1")
	assert.Error(t, err, "an expired lease is not found")
	_, ok, err = db.AcquireLease(ctx, "watch:1", "engine-b", time.Minute, nil)
	require.NoError(t, err)
	assert.True(t, ok, "an expired lease is acquired by another")
}
