// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j/dbtype"
	"github.com/stretchr/testify/assert"
)

func TestFindRunsQuery(t *testing.T) {
	query, params := findRunsQuery(time.Time{}, 0, nil)
	assert.Equal(t, "MATCH (r:CollectionRun) RETURN r ORDER BY r.started_at DESC, r.run_id", query,
		"an unfiltered query is not as expected")
	assert.Empty(t, params, "an unfiltered query has no parameters")

	query, params = findRunsQuery(time.Now(), 5, []string{"amass"})
	assert.Equal(t, "MATCH (r:CollectionRun) WHERE r.started_at >= $since AND r.tool IN $tools RETURN r "+
		"ORDER BY r.started_at DESC, r.run_id LIMIT $limit", query, "a filtered query is not as expected")
	assert.Equal(t, []string{"amass"}, params["tools"], "the tools are a parameter")
	assert.Equal(t, 5, params["limit"], "the limit is a parameter")
}

func TestNodeToRun(t *testing.T) {
	started := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	run, err := nodeToRun(map[string]any{"run_id": "r1", "tool": "amass", "status": "finished",
		"started_at": dbtype.LocalDateTime(started), "scope": `[{"type":"FQDN","key":"example.com"}]`,
		"metadata": `{"mode":"passive"}`})
	if assert.NoError(t, err, "reading a run node") {
		assert.Equal(t, "r1", run.ID, "the id is read")
		assert.True(t, run.StartedAt.Equal(started), "the start is read")
		assert.True(t, run.FinishedAt.IsZero(), "a missing finish is zero")
		assert.Equal(t, "example.com", run.Scope[0].Key, "the scope is read")
		assert.Equal(t, "passive", run.Metadata["mode"], "the metadata is read")
	}

	_, err = nodeToRun(map[string]any{"tool": "amass"})
	assert.Error(t, err, "a node without a run_id is refused")
}
