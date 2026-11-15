// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/owasp-amass/asset-db/types"
)

const runColumns = `run_id, tool, tool_version, external_id, status, started_at, finished_at, scope, metadata`

// StartRun implements repository.RunRecorder.
func (r *PostgresRepository) StartRun(ctx context.Context, run *types.CollectionRun) (*types.CollectionRun, error) {
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

	j := NewExecJob(ctx, `INSERT INTO public.collection_run (run_id, tool, tool_version, external_id, status,
        started_at, scope, metadata) VALUES (@id, @tool, @version, @external, @status, @started, @scope::jsonb,
        @metadata::jsonb)`, pgx.NamedArgs{"id": out.ID, "tool": out.Tool, "version": out.ToolVersion,
		"external": out.ExternalID, "status": out.Status, "started": out.StartedAt.UTC(), "scope": scope,
		"metadata": metadata}, func(pgconn.CommandTag) error { return nil })
	r.wpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	return &out, nil
}

// FinishRun implements repository.RunRecorder.
func (r *PostgresRepository) FinishRun(ctx context.Context, id, status string, finished time.Time) (*types.CollectionRun, error) {
	if !types.FinalRunStatus(status) {
		return nil, errors.New("a run finishes as finished, stopped or failed")
	}
	if finished.IsZero() {
		finished = time.Now()
	}

	j := NewExecJob(ctx, `UPDATE public.collection_run SET status = @status, finished_at = @finished,
        updated_at = now() WHERE run_id = @id AND status = 'running'`, pgx.NamedArgs{"id": id, "status": status,
		"finished": finished.UTC()}, func(tag pgconn.CommandTag) error {
		if tag.RowsAffected() == 0 {
			return errors.New("no running collection run has this id")
		}

		return nil
	})
	r.wpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	return r.FindRunById(ctx, id)
}

// FindRunById implements repository.RunRecorder.
func (r *PostgresRepository) FindRunById(ctx context.Context, id string) (*types.CollectionRun, error) {
	runs, err := r.queryRuns(ctx, `SELECT `+runColumns+` FROM public.collection_run WHERE run_id = @id`,
		pgx.NamedArgs{"id": id})
	if err != nil {
		return nil, err
	}
	if len(runs) == 0 {
		return nil, errors.New("no collection run has this id")
	}

	return runs[0], nil
}

// FindRuns implements repository.RunRecorder.
func (r *PostgresRepository) FindRuns(ctx context.Context, since time.Time, limit int, tools ...string) ([]*types.CollectionRun, error) {
	args := pgx.NamedArgs{"since": nil, "tools": nil, "limit": nil}
	if !since.IsZero() {
		args["since"] = since.UTC()
	}
	if len(tools) > 0 {
		args["tools"] = tools
	}
	if limit > 0 {
		args["limit"] = limit
	}

	return r.queryRuns(ctx, `SELECT `+runColumns+` FROM public.collection_run
        WHERE (@since::timestamp IS NULL OR started_at >= @since::timestamp)
          AND (@tools::text[] IS NULL OR tool = ANY(@tools::text[]))
        ORDER BY started_at DESC, run_id LIMIT @limit::integer`, args)
}

func (r *PostgresRepository) queryRuns(ctx context.Context, query string, args pgx.NamedArgs) ([]*types.CollectionRun, error) {
	var out []*types.CollectionRun
	j := NewRowsJob(ctx, query, args, func(rows pgx.Rows) error {
		for rows.Next() {
			var run types.CollectionRun
			var finished *time.Time
			var scope, metadata []byte
			if err := rows.Scan(&run.ID, &run.Tool, &run.ToolVersion, &run.ExternalID, &run.Status, &run.StartedAt,
				&finished, &scope, &metadata); err != nil {
				return err
			}

			run.StartedAt = run.StartedAt.In(time.UTC).Local()
			if finished != nil {
				run.FinishedAt = finished.In(time.UTC).Local()
			}
			if err := decodeRun(&run, scope, metadata); err != nil {
				return err
			}

			out = append(out, &run)
		}

		return rows.Err()
	})
	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	return out, nil
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

func decodeRun(run *types.CollectionRun, scope, metadata []byte) error {
	if len(scope) > 0 {
		if err := json.Unmarshal(scope, &run.Scope); err != nil {
			return err
		}
	}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &run.Metadata); err != nil {
			return err
		}
		if len(run.Metadata) == 0 {
			run.Metadata = nil
		}
	}

	return nil
}
