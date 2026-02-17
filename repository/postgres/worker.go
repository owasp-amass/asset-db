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
}

// WorkerConfig controls batching and concurrency behavior.
type WorkerConfig struct {
	// TxMode enables wrapping each job in a transaction with savepoints for isolation.
	TxMode bool

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
		cfg:      withDefaults(cfg),
		queue:    queue.NewQueue(),
		cancel:   cancel,
		flushSem: make(chan struct{}, cfg.FlushParallelism),
	}

	// Seed flush semaphore
	for range cfg.FlushParallelism {
		w.flushSem <- struct{}{}
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

	w.queue.Append(j)
}

// Shutdown stops the worker, flushes any remaining queued work, and waits for completion.
// This does not close the underlying pool (call pool.Close() if you own it).
func (w *Worker) Shutdown(ctx context.Context) error {
	var err error

	w.once.Do(func() {
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

			if w.cfg.TxMode {
				_ = w.flushBatchTxSavepoints(ctx, jobs)
			} else {
				_ = w.flushBatch(ctx, jobs)
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

func (w *Worker) flushBatch(ctx context.Context, items []job) error {
	return w.pool.AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
		var b pgx.Batch

		for _, item := range items {
			item.Queue(&b)
		}

		sctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()

		br := conn.SendBatch(sctx, &b)
		defer func() { _ = br.Close() }()

		for _, item := range items {
			item.Done() <- item.Decode(br)
			close(item.Done())
		}
		return nil
	})
}

func (w *Worker) flushBatchTxSavepoints(ctx context.Context, items []job) error {
	return w.pool.AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
		sctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()

		tx, err := conn.Begin(sctx)
		if err != nil {
			errToJobs(err, items)
			return err
		}
		defer func() { _ = tx.Rollback(sctx) }()

		const sp = "sp_job"
		// Record per-job outcome; don't publish yet
		results := make([]error, len(items))
		for i, item := range items {
			if err := item.GetCtx().Err(); err != nil {
				results[i] = err
				continue
			}

			if _, err := tx.Exec(sctx, "SAVEPOINT "+sp); err != nil {
				results[i] = wrapPgErr("savepoint", err)
				continue
			}

			runErr := item.RunTx(tx)
			if runErr != nil {
				if _, rbErr := tx.Exec(sctx, "ROLLBACK TO SAVEPOINT "+sp); rbErr != nil {
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
			if _, relErr := tx.Exec(sctx, "RELEASE SAVEPOINT "+sp); relErr != nil && runErr == nil {
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

		// Worker-level error should reflect commit failure (if any)
		return commitErr
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
