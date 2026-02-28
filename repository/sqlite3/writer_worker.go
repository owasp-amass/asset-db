// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/caffix/queue"
	_ "modernc.org/sqlite"
)

type writeJob struct {
	Ctx     context.Context
	Name    string
	SQLText string
	Args    []any
	Result  chan error
}

type writeWorker struct {
	db            *sql.DB
	conn          *sql.Conn
	cache         *Cache
	jobs          queue.Queue
	batchSize     int
	batchDuration time.Duration
	wg            sync.WaitGroup
	quit          chan struct{}
}

func newWriteWorker(db *sql.DB, batchSize int, batchDuration time.Duration) (*writeWorker, error) {
	ww := &writeWorker{
		db: db,
		cache: NewCache(CacheOptions{
			MaxBytes:   50 << 20,
			MaxEntries: 3000,
			IdleWeight: 5.0,
			AgeWeight:  0.2,
			HitWeight:  25.0,
			IdleTTL:    30 * time.Minute,
			AgeTTL:     12 * time.Hour,
			Shards:     32,
			SampleN:    64,
			CostFn: func(key string, _ *sql.Stmt) int64 {
				// key is SQL text:
				//  - len(sql) bytes
				//  - plus a fixed overhead fudge factor per entry
				return int64(len(key)) + 1024
			},
		}),
		jobs:          queue.NewQueue(),
		batchSize:     batchSize,
		batchDuration: batchDuration,
		quit:          make(chan struct{}),
	}

	if err := ww.acquireConn(); err != nil {
		return nil, err
	}

	ww.wg.Add(1)
	go ww.run()
	return ww, nil
}

func (ww *writeWorker) Submit(job *writeJob) {
	ww.jobs.Append(job)
}

func (ww *writeWorker) Close() {
	close(ww.quit)
	ww.wg.Wait()
	ww.cache.Close()
}

func (ww *writeWorker) getOrPrepare(ctx context.Context, key, sqlText string) (Lease, error) {
	if lease, ok := ww.cache.GetLease(key); ok {
		return lease, nil
	}

	ps, err := ww.conn.PrepareContext(ctx, sqlText)
	if err != nil && errors.Is(err, driver.ErrBadConn) {
		_ = ww.conn.Close()
		if err := ww.acquireConn(); err != nil {
			return Lease{}, err
		}
		ps, err = ww.conn.PrepareContext(ctx, sqlText)
	}
	if err != nil {
		return Lease{}, err
	}
	ww.cache.Put(key, ps)

	lease, ok := ww.cache.GetLease(key)
	if !ok {
		return Lease{}, errors.New("failed to acquire the prepared statement")
	}
	return lease, nil
}

func (ww *writeWorker) acquireConn() error {
	ww.cache.RetireAll()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := ww.db.Conn(ctx)
	if err != nil {
		return err
	}

	ww.conn = conn
	return nil
}

func (ww *writeWorker) run() {
	defer ww.wg.Done()

	batchdur := time.NewTicker(ww.batchDuration)
	defer batchdur.Stop()

	check := time.NewTicker(5 * time.Millisecond)
	defer check.Stop()

	var txlist []*writeJob
	commit := func(jobs []*writeJob) {
		remaining, err := ww.flushJobs(jobs)
		if err == nil || len(remaining) == 0 {
			return
		}

		if failed, err := ww.flushJobs(remaining); err != nil && len(failed) > 0 {
			errToJobs(failed, err)
		}
	}

	queueCheck := func() {
		for !ww.jobs.Empty() {
			job, ok := ww.jobs.Next()
			if !ok || job == nil {
				continue
			}

			wj, valid := job.(*writeJob)
			if !valid || wj.Result == nil {
				continue
			}

			if wj.Ctx == nil {
				wj.Result <- errors.New("context is nil")
				continue
			}

			if err := wj.Ctx.Err(); err != nil {
				wj.Result <- err
				continue
			}

			if wj.Name == "" || wj.SQLText == "" {
				wj.Result <- errors.New("invalid write job")
				continue
			}

			txlist = append(txlist, wj)
			if len(txlist) >= ww.batchSize {
				commit(txlist)
				txlist = nil
				return
			}
		}
	}

	for {
		select {
		case <-ww.quit:
			for !ww.jobs.Empty() {
				queueCheck()
			}
			commit(txlist)
			txlist = nil
			return
		case <-batchdur.C:
			queueCheck()
			commit(txlist)
			txlist = nil
		case <-ww.jobs.Signal():
			queueCheck()
		}
	}
}

func (ww *writeWorker) flushJobs(jobs []*writeJob) ([]*writeJob, error) {
	if len(jobs) == 0 {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := ww.conn.BeginTx(ctx, nil)
	if err != nil {
		if errors.Is(err, driver.ErrBadConn) {
			_ = ww.conn.Close()
			if err := ww.acquireConn(); err != nil {
				return jobs, err
			}
			tx, err = ww.conn.BeginTx(ctx, nil)
		}
		if err != nil {
			return jobs, err
		}
	}
	defer func() { _ = tx.Rollback() }()

	// Track jobs that executed successfully and are pending COMMIT.
	// If COMMIT fails, all of these must be reported as failed.
	var pendingCommit []*writeJob

	for i, job := range jobs {
		if err := job.Ctx.Err(); err != nil {
			job.Result <- err
			continue
		}

		// Per-job savepoint to isolate failures
		sp := fmt.Sprintf("sp_%d", i)

		if _, err := tx.ExecContext(job.Ctx, "SAVEPOINT "+sp); err != nil {
			job.Result <- err
			continue
		}

		lease, err := ww.getOrPrepare(job.Ctx, job.Name, job.SQLText)
		if err != nil {
			// Roll back just this job, keep going
			_, _ = tx.ExecContext(job.Ctx, "ROLLBACK TO SAVEPOINT "+sp)
			_, _ = tx.ExecContext(job.Ctx, "RELEASE SAVEPOINT "+sp)
			job.Result <- err
			continue
		}
		defer lease.Release()

		_, err = tx.StmtContext(job.Ctx, lease.Stmt).Exec(job.Args...)
		if err != nil {
			// Roll back just this job, keep going
			_, _ = tx.ExecContext(job.Ctx, "ROLLBACK TO SAVEPOINT "+sp)
			_, _ = tx.ExecContext(job.Ctx, "RELEASE SAVEPOINT "+sp)
			job.Result <- err
			continue
		}

		// Success for this job so far; release savepoint
		if _, err := tx.ExecContext(job.Ctx, "RELEASE SAVEPOINT "+sp); err != nil {
			// If we can't release, treat as job failure and isolate
			_, _ = tx.ExecContext(job.Ctx, "ROLLBACK TO SAVEPOINT "+sp)
			_, _ = tx.ExecContext(job.Ctx, "RELEASE SAVEPOINT "+sp)
			job.Result <- err
			continue
		}

		// Defer "success" until COMMIT is successful
		pendingCommit = append(pendingCommit, job)
	}

	// If nothing succeeded, we're done (no need to commit)
	if len(pendingCommit) == 0 {
		return nil, nil
	}

	if err := tx.Commit(); err != nil {
		// None of the "pendingCommit" jobs were durably written. Send them back as failed
		return pendingCommit, err
	}

	// Now we can mark all "pendingCommit" jobs as successful
	errToJobs(pendingCommit, nil)
	return nil, nil
}

func errToJobs(jobs []*writeJob, err error) {
	for _, job := range jobs {
		job.Result <- err
	}
}
