// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j/dbtype"
	"github.com/owasp-amass/asset-db/types"
)

// Collection runs are CollectionRun nodes, apart from the graph of assets;
// their scope and metadata are JSON text.

// StartRun implements repository.RunRecorder.
func (neo *NeoRepository) StartRun(ctx context.Context, run *types.CollectionRun) (*types.CollectionRun, error) {
	if err := run.Validate(); err != nil {
		return nil, err
	}

	out := *run
	out.ID = uuid.NewString()
	out.Status = types.RunRunning
	out.FinishedAt = time.Time{}
	if out.StartedAt.IsZero() {
		out.StartedAt = time.Now()
	}

	scope, err := json.Marshal(nonNilScope(out.Scope))
	if err != nil {
		return nil, err
	}

	metadata, err := json.Marshal(nonNilMetadata(out.Metadata))
	if err != nil {
		return nil, err
	}

	_, err = neo.runQuery(ctx, "CREATE (r:CollectionRun $props) RETURN r", map[string]any{"props": map[string]any{
		"run_id": out.ID, "tool": out.Tool, "tool_version": out.ToolVersion, "external_id": out.ExternalID,
		"status": out.Status, "started_at": timeToNeo4jTime(out.StartedAt), "scope": string(scope),
		"metadata": string(metadata)}})
	if err != nil {
		return nil, err
	}

	return &out, nil
}

// FinishRun implements repository.RunRecorder.
func (neo *NeoRepository) FinishRun(ctx context.Context, id, status string, finished time.Time) (*types.CollectionRun, error) {
	if !types.FinalRunStatus(status) {
		return nil, errors.New("a run finishes as finished, stopped or failed")
	}
	if finished.IsZero() {
		finished = time.Now()
	}

	runs, err := neo.runQuery(ctx, "MATCH (r:CollectionRun {run_id: $id, status: 'running'}) "+
		"SET r.status = $status, r.finished_at = $finished RETURN r",
		map[string]any{"id": id, "status": status, "finished": timeToNeo4jTime(finished)})
	if err != nil {
		return nil, err
	}
	if len(runs) == 0 {
		return nil, errors.New("no running collection run has this id")
	}

	return runs[0], nil
}

// FindRunById implements repository.RunRecorder.
func (neo *NeoRepository) FindRunById(ctx context.Context, id string) (*types.CollectionRun, error) {
	runs, err := neo.runQuery(ctx, "MATCH (r:CollectionRun {run_id: $id}) RETURN r", map[string]any{"id": id})
	if err != nil {
		return nil, err
	}
	if len(runs) == 0 {
		return nil, errors.New("no collection run has this id")
	}

	return runs[0], nil
}

// FindRuns implements repository.RunRecorder.
func (neo *NeoRepository) FindRuns(ctx context.Context, since time.Time, limit int, tools ...string) ([]*types.CollectionRun, error) {
	query, params := findRunsQuery(since, limit, tools)
	return neo.runQuery(ctx, query, params)
}

func findRunsQuery(since time.Time, limit int, tools []string) (string, map[string]any) {
	params := map[string]any{}
	var conds []string
	if !since.IsZero() {
		params["since"] = timeToNeo4jTime(since)
		conds = append(conds, "r.started_at >= $since")
	}
	if len(tools) > 0 {
		params["tools"] = tools
		conds = append(conds, "r.tool IN $tools")
	}

	query := "MATCH (r:CollectionRun)" + where(conds...) + " RETURN r ORDER BY r.started_at DESC, r.run_id"
	return query + limitClause(limit, params), params
}

func (neo *NeoRepository) runQuery(ctx context.Context, query string, params map[string]any) ([]*types.CollectionRun, error) {
	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(tctx, neo.DB, query, params, neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname))
	if err != nil {
		return nil, err
	}

	var out []*types.CollectionRun
	for _, rec := range result.Records {
		node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](rec, "r")
		if err != nil || isnil {
			continue
		}

		run, err := nodeToRun(node.Props)
		if err != nil {
			return nil, err
		}

		out = append(out, run)
	}

	return out, nil
}

func nodeToRun(p map[string]any) (*types.CollectionRun, error) {
	run := &types.CollectionRun{}
	run.ID, _ = p["run_id"].(string)
	run.Tool, _ = p["tool"].(string)
	run.ToolVersion, _ = p["tool_version"].(string)
	run.ExternalID, _ = p["external_id"].(string)
	run.Status, _ = p["status"].(string)
	if t, ok := p["started_at"].(dbtype.LocalDateTime); ok {
		run.StartedAt = neo4jTimeToTime(t)
	}
	if t, ok := p["finished_at"].(dbtype.LocalDateTime); ok {
		run.FinishedAt = neo4jTimeToTime(t)
	}
	if s, ok := p["scope"].(string); ok && s != "" {
		if err := json.Unmarshal([]byte(s), &run.Scope); err != nil {
			return nil, err
		}
	}
	if s, ok := p["metadata"].(string); ok && s != "" {
		if err := json.Unmarshal([]byte(s), &run.Metadata); err != nil {
			return nil, err
		}
		if len(run.Metadata) == 0 {
			run.Metadata = nil
		}
	}
	if run.ID == "" {
		return nil, errors.New("a collection run node has no run_id")
	}

	return run, nil
}

func nonNilScope(s []types.RunTarget) []types.RunTarget {
	if s == nil {
		return []types.RunTarget{}
	}

	return s
}

func nonNilMetadata(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}

	return m
}
