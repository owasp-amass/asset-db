// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
)

// A batch with a failing write is run again with savepoints, so only the
// failing job reports an error and the others' writes are kept.
func TestWorkerBatchWithFailingJob(t *testing.T) {
	repo := valueFinderRepo(t)
	ctx := context.Background()

	create := NewExecJob(ctx, `CREATE TABLE IF NOT EXISTS worker_paths (x int PRIMARY KEY)`, nil, nil)
	repo.wpool.Submit(create)
	if !assert.NoError(t, create.Wait(), "create the test table") {
		return
	}

	// A long delay puts every job in the same batch.
	pool, err := pgxpool.New(ctx, repo.dsn)
	if !assert.NoError(t, err, "open a pool for the batching worker") {
		return
	}

	w := NewWorkerWithPool(ctx, pool, withDefaults(WorkerConfig{PoolMaxConns: 1,
		MaxBatchDelay: 200 * time.Millisecond}))
	defer func() { _ = w.Shutdown(ctx) }()

	jobs := make([]job, 5)
	for i := range jobs {
		sql := `INSERT INTO worker_paths (x) VALUES (@x)`
		if i == 2 {
			sql = `SELECT 1 / (@x::int - @x::int)`
		}

		jobs[i] = NewExecJob(ctx, sql, pgx.NamedArgs{"x": i}, func(pgconn.CommandTag) error { return nil })
	}

	var wg sync.WaitGroup
	errs := make([]error, len(jobs))
	for i, j := range jobs {
		w.Submit(j)
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = j.Wait()
		}()
	}

	wg.Wait()
	for i, err := range errs {
		if i == 2 {
			assert.Error(t, err, "the failing job reports its error")
		} else {
			assert.NoError(t, err, fmt.Sprintf("job %d is not failed by another job's error", i))
		}
	}

	var n int
	count := NewRowJob(ctx, `SELECT count(*) FROM worker_paths`, nil, func(row pgx.Row) error {
		return row.Scan(&n)
	})
	repo.rpool.Submit(count)
	assert.NoError(t, count.Wait(), "count the stored rows")
	assert.Equal(t, 4, n, "the other jobs' rows are stored")
}

// Reads run directly on the reader pool, and are refused after shutdown.
func TestWorkerDirectReads(t *testing.T) {
	repo := valueFinderRepo(t)
	ctx := context.Background()
	assert.True(t, repo.rcfg.Direct, "the reader runs jobs directly")

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			var got int
			j := NewRowJob(ctx, `SELECT @x::int`, pgx.NamedArgs{"x": i}, func(row pgx.Row) error {
				return row.Scan(&got)
			})
			repo.rpool.Submit(j)
			assert.NoError(t, j.Wait(), "a direct read succeeds")
			assert.Equal(t, i, got, "a direct read returns its own result")
		}()
	}

	wg.Wait()

	pool, err := pgxpool.New(ctx, repo.dsn)
	if !assert.NoError(t, err, "open a pool for the direct worker") {
		return
	}

	w := NewWorkerWithPool(ctx, pool, withDefaults(WorkerConfig{Direct: true}))
	assert.NoError(t, w.Shutdown(ctx), "shut the direct worker down")

	j := NewRowJob(ctx, `SELECT 1`, nil, nil)
	w.Submit(j)
	assert.Error(t, j.Wait(), "a read after shutdown is refused")
}
