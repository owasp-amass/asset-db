// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Runs from any tool are recorded, found newest first, filtered by start
// and tool, and finished once.
func TestPostgresCollectionRuns(t *testing.T) {
	db := valueFinderRepo(t)
	ctx := context.Background()

	_, err := db.StartRun(ctx, &types.CollectionRun{})
	assert.Error(t, err, "a run must name its tool")
	_, err = db.StartRun(ctx, &types.CollectionRun{Tool: "x", Scope: []types.RunTarget{{Type: "Nonsense", Key: "a"}}})
	assert.Error(t, err, "a scope target must be an Open Asset Model asset type")

	start := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
	first, err := db.StartRun(ctx, &types.CollectionRun{Tool: "amass", ToolVersion: "v5", ExternalID: "session-1",
		StartedAt: start, Scope: []types.RunTarget{{Type: oam.FQDN, Key: "example.com"},
			{Type: oam.Netblock, Key: "192.0.2.0/24"}}, Metadata: map[string]any{"mode": "active"}})
	require.NoError(t, err, "starting a run")
	assert.NotEmpty(t, first.ID, "a started run has an id")
	assert.Equal(t, types.RunRunning, first.Status, "a started run is running")

	second, err := db.StartRun(ctx, &types.CollectionRun{Tool: "nmap-import"})
	require.NoError(t, err, "starting another tool's run")

	runs, err := db.FindRuns(ctx, time.Time{}, 0)
	require.NoError(t, err, "finding runs")
	if assert.Len(t, runs, 2, "both runs are found") {
		assert.Equal(t, second.ID, runs[0].ID, "runs are newest first")
		assert.Equal(t, "session-1", runs[1].ExternalID, "the tool's own id is kept")
		assert.Equal(t, []types.RunTarget{{Type: oam.FQDN, Key: "example.com"}, {Type: oam.Netblock,
			Key: "192.0.2.0/24"}}, runs[1].Scope, "the scope is kept")
		assert.Equal(t, "active", runs[1].Metadata["mode"], "the metadata is kept")
		assert.True(t, runs[1].StartedAt.Equal(start), "the start time is kept: %v", runs[1].StartedAt)
		assert.True(t, runs[1].FinishedAt.IsZero(), "a running run has not finished")
	}

	runs, err = db.FindRuns(ctx, time.Time{}, 0, "amass")
	require.NoError(t, err, "finding one tool's runs")
	assert.Len(t, runs, 1, "only the named tool's runs are found")
	runs, err = db.FindRuns(ctx, time.Now().Add(-time.Minute), 0)
	require.NoError(t, err, "finding recent runs")
	assert.Len(t, runs, 1, "only runs started since are found")
	runs, err = db.FindRuns(ctx, time.Time{}, 1)
	require.NoError(t, err, "finding the latest run")
	assert.Len(t, runs, 1, "the limit is kept")

	_, err = db.FinishRun(ctx, first.ID, types.RunRunning, time.Time{})
	assert.Error(t, err, "running is not a final status")
	done, err := db.FinishRun(ctx, first.ID, types.RunFinished, time.Time{})
	require.NoError(t, err, "finishing the run")
	assert.Equal(t, types.RunFinished, done.Status, "the run is finished")
	assert.False(t, done.FinishedAt.IsZero(), "a finished run has its finish time")
	_, err = db.FinishRun(ctx, first.ID, types.RunStopped, time.Time{})
	assert.Error(t, err, "a run finishes once")

	found, err := db.FindRunById(ctx, first.ID)
	require.NoError(t, err, "finding the run by id")
	assert.Equal(t, types.RunFinished, found.Status, "the finished run is found finished")
	_, err = db.FindRunById(ctx, "no-such-run")
	assert.Error(t, err, "an unknown id is not found")
}
