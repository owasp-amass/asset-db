// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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

	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		return nil, fmt.Errorf("create pgxpool: %w", err)
	}

	// ---- Fail fast: verify connectivity now ----
	deadline := time.Now().Add(15 * time.Second)
	for {
		pctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)

		err = pool.Ping(pctx)
		cancel()
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
	// If ctx is canceled before enqueue, fail fast.
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
		go func(items []job) {
			defer w.wg.Done()
			defer func() { w.flushSem <- struct{}{} }()

			var err error
			for range 5 {
				err = w.flushBatch(ctx, items)
				if err == nil {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			if err != nil {
				for _, j := range items {
					j.Done() <- err
					close(j.Done())
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
			// Drain channel until closed, then flush whatever remains.
			w.queue.Process(func(element any) {
				if j, ok := element.(job); ok {
					batch = append(batch, j)
					if len(batch) >= w.cfg.MaxBatchSize {
						flush(batch)
						batch = nil
					}
				}
			})
			flush(batch)
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

		for _, j := range items {
			j.Queue(&b)
		}

		br := conn.SendBatch(ctx, &b)
		defer func() { _ = br.Close() }()

		for _, j := range items {
			j.Done() <- j.Decode(br)
			close(j.Done())
		}
		return nil
	})
}
