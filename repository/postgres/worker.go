// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/caffix/queue"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Worker accepts jobs, batches them, and flushes them to PostgreSQL.
type Worker struct {
	pool     *pgxpool.Pool
	cfg      WorkerConfig
	queue    queue.Queue
	wg       sync.WaitGroup
	cancel   context.CancelFunc
	once     sync.Once
	flushSem chan struct{} // limits concurrent flushes

	// closeMu guards closed: a direct job is not started after Shutdown.
	closeMu sync.RWMutex
	closed  bool
}

// WorkerConfig controls batching and concurrency behavior.
type WorkerConfig struct {
	// PoolMinConns sets pgxpool MinConns. If 0, defaults to 0.
	PoolMinConns int32

	// PoolMaxConns sets pgxpool MaxConns. If 0, defaults to 8.
	PoolMaxConns int32

	// MaxConnLifetime sets pgxpool MaxConnLifetime. If 0, defaults to pgxpool default.
	MaxConnLifetime time.Duration

	// MaxConnIdleTime sets pgxpool MaxConnIdleTime. If 0, defaults to pgxpool default.
	MaxConnIdleTime time.Duration

	// HealthCheckPeriod sets pgxpool HealthCheckPeriod. If 0, defaults to pgxpool default.
	HealthCheckPeriod time.Duration

	// StatementTimeout sets pgxpool StatementTimeout. If 0, defaults to pgxpool default.
	StatementTimeout time.Duration

	// ApplicationName sets pgxpool ApplicationName. If empty, defaults to pgxpool default.
	ApplicationName string

	// MaxBatchSize is the maximum number of jobs processed per batch flush.
	// If 0, defaults to 256.
	MaxBatchSize int

	// MaxBatchDelay is the max time to wait before flushing a partially full batch.
	// If 0, defaults to 5ms.
	MaxBatchDelay time.Duration

	// FlushParallelism is how many batch flush goroutines run concurrently.
	// Each flush acquires a pooled connection (and can also use a TX).
	// If 0, defaults to PoolMaxConns (or 8).
	FlushParallelism int

	// Direct runs each job at once on its own pooled connection, outside a
	// transaction, instead of batching jobs into transactions. Reads use it:
	// a batched read waits for the batch to fill and for every job before
	// it, and pays for a savepoint and its release. The pool's MaxConns
	// bounds how many direct jobs run at the same time.
	Direct bool
}

func withDefaults(cfg WorkerConfig) WorkerConfig {
	if cfg.PoolMaxConns == 0 {
		cfg.PoolMaxConns = 8
	}
	if cfg.MaxBatchSize == 0 {
		cfg.MaxBatchSize = 100
	}
	if cfg.MaxBatchDelay == 0 {
		cfg.MaxBatchDelay = time.Millisecond
	}
	if cfg.FlushParallelism == 0 {
		// default: one flush goroutine per connection slot
		cfg.FlushParallelism = int(cfg.PoolMaxConns)
		if cfg.FlushParallelism <= 0 {
			cfg.FlushParallelism = 8
		}
	}

	return cfg
}

// NewWorker creates a pgxpool with the provided connection string and starts the worker.
func NewWorker(ctx context.Context, connString string, cfg WorkerConfig) (*Worker, error) {
	pcfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parse pgxpool config: %w", err)
	}

	if cfg.PoolMinConns >= 0 {
		pcfg.MinConns = cfg.PoolMinConns
	}
	if cfg.PoolMaxConns > 0 {
		pcfg.MaxConns = cfg.PoolMaxConns
	}
	if cfg.MaxConnLifetime > 0 {
		pcfg.MaxConnLifetime = cfg.MaxConnLifetime
	}
	if cfg.MaxConnIdleTime > 0 {
		pcfg.MaxConnIdleTime = cfg.MaxConnIdleTime
	}
	if cfg.HealthCheckPeriod > 0 {
		pcfg.HealthCheckPeriod = cfg.HealthCheckPeriod
	}
	if cfg.StatementTimeout > 0 {
		timeoutMS := int(cfg.StatementTimeout.Milliseconds())
		pcfg.ConnConfig.RuntimeParams["statement_timeout"] = fmt.Sprintf("%d", timeoutMS)
	}
	if cfg.ApplicationName != "" {
		pcfg.ConnConfig.RuntimeParams["application_name"] = cfg.ApplicationName
	}

	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(pctx, pcfg)
	if err != nil {
		return nil, fmt.Errorf("create pgxpool: %w", err)
	}

	// ---- Fail fast: verify connectivity now ----
	deadline := time.Now().Add(15 * time.Second)
	for {
		pictx, picancel := context.WithTimeout(ctx, 2*time.Second)

		err = pool.Ping(pictx)
		picancel()
		if err == nil {
			break
		}

		if time.Now().After(deadline) {
			pool.Close()
			return nil, fmt.Errorf("failed to connect to database: %w", err)
		}

		time.Sleep(200 * time.Millisecond)
	}

	return NewWorkerWithPool(ctx, pool, cfg), nil
}

// NewWorkerWithPool uses an existing pool (useful for SDKs that own the pool elsewhere).
func NewWorkerWithPool(ctx context.Context, pool *pgxpool.Pool, cfg WorkerConfig) *Worker {
	wctx, cancel := context.WithCancel(ctx)
	w := &Worker{
		pool:     pool,
		cfg:      cfg,
		queue:    queue.NewQueue(),
		cancel:   cancel,
		flushSem: make(chan struct{}, cfg.FlushParallelism),
	}

	// Seed flush semaphore
	for range cfg.FlushParallelism {
		w.flushSem <- struct{}{}
	}
	if cfg.Direct {
		return w
	}

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.runAggregator(wctx)
	}()

	return w
}

func (w *Worker) Submit(j job) {
	// If ctx is canceled before enqueue, fail fast
	select {
	case <-j.GetCtx().Done():
		return
	default:
	}

	if w.cfg.Direct {
		w.closeMu.RLock()
		defer w.closeMu.RUnlock()
		if w.closed {
			j.Done() <- errors.New("worker pool shutting down")
			close(j.Done())
			return
		}

		w.wg.Add(1)
		go w.runDirect(j)
		return
	}

	w.queue.Append(j)
}

// runDirect runs one job on a pooled connection, outside a transaction.
func (w *Worker) runDirect(j job) {
	defer w.wg.Done()

	err := w.pool.AcquireFunc(j.GetCtx(), func(conn *pgxpool.Conn) error {
		return j.RunTx(conn)
	})

	j.Done() <- err
	close(j.Done())
}

// Shutdown stops the worker, flushes any remaining queued work, and waits for completion.
// This does not close the underlying pool (call pool.Close() if you own it).
func (w *Worker) Shutdown(ctx context.Context) error {
	var err error

	w.once.Do(func() {
		w.closeMu.Lock()
		w.closed = true
		w.closeMu.Unlock()
		w.cancel()

		done := make(chan struct{})
		go func() {
			w.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-ctx.Done():
			err = ctx.Err()
		}

		w.pool.Close()
	})

	return err
}

func (w *Worker) runAggregator(ctx context.Context) {
	// timer drives MaxBatchDelay flushes
	timer := time.NewTimer(w.cfg.MaxBatchDelay)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()

	var batch []job
	flush := func(items []job) {
		if len(items) == 0 {
			return
		}
		// Acquire flush slot (limits concurrent flush work)
		select {
		case <-ctx.Done():
			// Fail all outstanding items if shutting down
			for _, j := range items {
				j.Done() <- errors.New("worker pool shutting down")
				close(j.Done())
			}

			return
		case <-w.flushSem:
		}

		w.wg.Add(1)
		go func(jobs []job) {
			defer w.wg.Done()
			defer func() { w.flushSem <- struct{}{} }()

			// Most batches have no failing job, so they are first sent as
			// one pipelined batch without savepoints (one round trip for the
			// batch instead of three per job); a batch with a failing job is
			// rolled back and run again with savepoints, which keep the other
			// jobs' writes.
			if w.flushBatchTx(ctx, jobs) {
				return
			}

			for i := range 5 {
				if err := w.flushBatchTxSavepoints(ctx, jobs); err == nil {
					break
				} else if i == 4 {
					errToJobs(err, jobs)
				} else {
					time.Sleep(500 * time.Millisecond)
				}
			}
		}(items)
	}

	resetTimer := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		timer.Reset(w.cfg.MaxBatchDelay)
	}

	for {
		// If shutting down and channel closed/drained, flush remainder and exit
		select {
		case <-ctx.Done():
			// Drain channel until closed, then flush whatever remains
			w.queue.Process(func(element any) {
				if j, ok := element.(job); ok {
					select {
					case <-j.GetCtx().Done():
						j.Done() <- errors.New("context expired")
						return
					default:
					}

					batch = append(batch, j)
					if len(batch) >= w.cfg.MaxBatchSize {
						flush(batch)
						batch = nil
					}
				}
			})
			flush(batch)
			batch = nil
			return
		default:
		}

		select {
		case <-w.queue.Signal():
			w.queue.Process(func(element any) {
				j, ok := element.(job)
				if !ok {
					return
				}

				select {
				case <-j.GetCtx().Done():
					j.Done() <- errors.New("context expired")
					return
				default:
				}

				batch = append(batch, j)
				if len(batch) == 1 {
					// first item starts the timer window
					resetTimer()
				}
				if len(batch) >= w.cfg.MaxBatchSize {
					flush(batch)
					batch = nil
					resetTimer()
				}
			})
		case <-timer.C:
			flush(batch)
			batch = nil
			resetTimer()
		}
	}
}

// flushBatchTx sends the jobs in one transaction as one pipelined batch,
// without savepoints, and reports whether it committed and published their
// results. When any job
// fails, or the commit does, nothing is published and the caller runs the
// batch again with savepoints. Jobs only scan into their own variables, so
// running a job again replaces what the first run scanned.
func (w *Worker) flushBatchTx(ctx context.Context, items []job) bool {
	ok := false
	_ = w.pool.AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
		sctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()

		tx, err := conn.Begin(sctx)
		if err != nil {
			return err
		}

		defer func() { _ = tx.Rollback(sctx) }()

		results := make([]error, len(items))
		batch := &pgx.Batch{}
		for i, item := range items {
			if err := item.GetCtx().Err(); err != nil {
				results[i] = err
				continue
			}

			item.Queue(batch)
		}
		if batch.Len() > 0 {
			if err := tx.SendBatch(sctx, batch).Close(); err != nil {
				return err
			}
		}
		if err := tx.Commit(sctx); err != nil {
			return err
		}

		ok = true
		for i, item := range items {
			item.Done() <- results[i]
			close(item.Done())
		}

		return nil
	})

	return ok
}

func (w *Worker) flushBatchTxSavepoints(ctx context.Context, items []job) error {
	return w.pool.AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
		sctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()

		tx, err := conn.Begin(sctx)
		if err != nil {
			return err
		}

		defer func() { _ = tx.Rollback(sctx) }()

		const sp = "sp_job"
		// Record per-job outcome; don't publish yet
		results := make([]error, len(items))
		for i, item := range items {
			jctx := item.GetCtx()

			if err := jctx.Err(); err != nil {
				results[i] = err
				continue
			}

			if _, err := tx.Exec(jctx, "SAVEPOINT "+sp); err != nil {
				results[i] = wrapPgErr("savepoint", err)
				continue
			}

			runErr := item.RunTx(tx)
			if runErr != nil {
				if _, rbErr := tx.Exec(jctx, "ROLLBACK TO SAVEPOINT "+sp); rbErr != nil {
					rbErr = wrapPgErr("rollback to savepoint", rbErr)
					// tx is likely unusable; fail remaining jobs and abort
					fErr := fmt.Errorf("job error: %v; rollback-to-savepoint failed: %w", runErr, rbErr)
					for k := i; k < len(items); k++ {
						results[k] = fErr
					}

					// We'll fall through to COMMIT (which should fail)
					break
				}
			}
			// In PG, RELEASE after ROLLBACK TO is OK, but if RELEASE fails the tx may be unhealthy
			if _, relErr := tx.Exec(jctx, "RELEASE SAVEPOINT "+sp); relErr != nil && runErr == nil {
				runErr = wrapPgErr("release savepoint", relErr)
			}

			results[i] = runErr
		}

		commitErr := tx.Commit(sctx)
		if commitErr != nil {
			commitErr = wrapPgErr("commit", commitErr)
		}

		// Publish results *after* commit decision
		for i, item := range items {
			errToSend := results[i]

			// If commit failed, any previously-successful job must be marked failed
			if commitErr != nil && errToSend == nil {
				errToSend = commitErr
			}

			// Always send exactly one result per job
			item.Done() <- errToSend
			close(item.Done())
		}

		// worker-level return value will be nil, since job errors were returned
		return nil
	})
}

func errToJobs(err error, items []job) {
	for _, item := range items {
		select {
		case <-item.GetCtx().Done():
			item.Done() <- errors.New("context expired")
		default:
			item.Done() <- err
		}

		close(item.Done())
	}
}
