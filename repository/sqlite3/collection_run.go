// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/asset-db/types"
)

// runTimeLayout is how run times are stored: UTC, fixed width, so they
// compare as text.
const runTimeLayout = "2006-01-02 15:04:05.000"

const runColumns = `run_id, tool, tool_version, external_id, status, started_at, finished_at, scope, metadata`

// StartRun implements repository.RunRecorder.
func (r *SqliteRepository) StartRun(ctx context.Context, run *types.CollectionRun) (*types.CollectionRun, error) {
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

	scope, metadata, err := encodeRun(&out)
	if err != nil {
		return nil, err
	}

	err = r.write(ctx, "collection_run.start", `INSERT INTO collection_run (run_id, tool, tool_version, external_id,
        status, started_at, scope, metadata) VALUES (:id, :tool, :version, :external, :status, :started, :scope,
        :metadata)`, sql.Named("id", out.ID), sql.Named("tool", out.Tool), sql.Named("version", out.ToolVersion),
		sql.Named("external", out.ExternalID), sql.Named("status", out.Status),
		sql.Named("started", out.StartedAt.UTC().Format(runTimeLayout)), sql.Named("scope", scope),
		sql.Named("metadata", metadata))
	if err != nil {
		return nil, err
	}

	return &out, nil
}

// FinishRun implements repository.RunRecorder.
func (r *SqliteRepository) FinishRun(ctx context.Context, id, status string, finished time.Time) (*types.CollectionRun, error) {
	if !types.FinalRunStatus(status) {
		return nil, errors.New("a run finishes as finished, stopped or failed")
	}

	run, err := r.FindRunById(ctx, id)
	if err != nil {
		return nil, err
	}
	if run.Status != types.RunRunning {
		return nil, errors.New("no running collection run has this id")
	}
	if finished.IsZero() {
		finished = time.Now()
	}

	err = r.write(ctx, "collection_run.finish", `UPDATE collection_run SET status = :status, finished_at = :finished,
        updated_at = strftime('%Y-%m-%d %H:%M:%f','now') WHERE run_id = :id AND status = 'running'`,
		sql.Named("id", id), sql.Named("status", status),
		sql.Named("finished", finished.UTC().Format(runTimeLayout)))
	if err != nil {
		return nil, err
	}

	return r.FindRunById(ctx, id)
}

// FindRunById implements repository.RunRecorder.
func (r *SqliteRepository) FindRunById(ctx context.Context, id string) (*types.CollectionRun, error) {
	runs, err := r.queryRuns(ctx, "collection_run.by_id", `SELECT `+runColumns+` FROM collection_run
        WHERE run_id = :id`, sql.Named("id", id))
	if err != nil {
		return nil, err
	}
	if len(runs) == 0 {
		return nil, errors.New("no collection run has this id")
	}

	return runs[0], nil
}

// FindRuns implements repository.RunRecorder.
func (r *SqliteRepository) FindRuns(ctx context.Context, since time.Time, limit int, tools ...string) ([]*types.CollectionRun, error) {
	var where []string
	var args []any
	if !since.IsZero() {
		where = append(where, "started_at >= :since")
		args = append(args, sql.Named("since", since.UTC().Format(runTimeLayout)))
	}
	if len(tools) > 0 {
		in, targs := inClause(tools)
		where = append(where, "tool IN "+in)
		args = append(args, targs...)
	}

	q := `SELECT ` + runColumns + ` FROM collection_run`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}

	q += " ORDER BY started_at DESC, run_id"
	if limit > 0 {
		q += " LIMIT :limit"
		args = append(args, sql.Named("limit", limit))
	}

	// the reader keeps a prepared statement by name: each shape of the query
	// is named by its text
	return r.queryRuns(ctx, q, q, args...)
}

func (r *SqliteRepository) write(ctx context.Context, name, query string, args ...any) error {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{Ctx: ctx, Name: name, SQLText: query, Args: args, Result: done})
	return <-done
}

func (r *SqliteRepository) queryRuns(ctx context.Context, name, query string, args ...any) ([]*types.CollectionRun, error) {
	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{Ctx: ctx, Name: name, SQLText: query, Args: args, Result: ch})
	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	defer func() { _ = result.Rows.Close() }()

	var out []*types.CollectionRun
	for result.Rows.Next() {
		var run types.CollectionRun
		var started, scope, metadata string
		var finished sql.NullString
		if err := result.Rows.Scan(&run.ID, &run.Tool, &run.ToolVersion, &run.ExternalID, &run.Status, &started,
			&finished, &scope, &metadata); err != nil {
			return nil, err
		}

		t, err := parseTimestamp(started)
		if err != nil {
			return nil, err
		}

		run.StartedAt = t.In(time.UTC).Local()
		if finished.Valid && finished.String != "" {
			if t, err = parseTimestamp(finished.String); err != nil {
				return nil, err
			}

			run.FinishedAt = t.In(time.UTC).Local()
		}
		if err := json.Unmarshal([]byte(scope), &run.Scope); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(metadata), &run.Metadata); err != nil {
			return nil, err
		}
		if len(run.Metadata) == 0 {
			run.Metadata = nil
		}

		out = append(out, &run)
	}

	return out, result.Rows.Err()
}

func encodeRun(run *types.CollectionRun) (string, string, error) {
	scope := run.Scope
	if scope == nil {
		scope = []types.RunTarget{}
	}

	s, err := json.Marshal(scope)
	if err != nil {
		return "", "", err
	}

	metadata := run.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}

	m, err := json.Marshal(metadata)
	if err != nil {
		return "", "", err
	}

	return string(s), string(m), nil
}
