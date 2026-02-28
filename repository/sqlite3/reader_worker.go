// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync"
	"time"

	"github.com/caffix/queue"
	_ "modernc.org/sqlite"
)

type rowReadResult struct {
	Row *sql.Row
	Err error
}

type rowReadJob struct {
	Ctx     context.Context
	Name    string
	SQLText string
	Args    []any
	Result  chan *rowReadResult
}

type rowsReadResult struct {
	Rows *sql.Rows
	Err  error
}

type rowsReadJob struct {
	Ctx     context.Context
	Name    string
	SQLText string
	Args    []any
	Result  chan *rowsReadResult
}

type readerWorkerPool struct {
	workers []*readerWorker
	next    int
	mu      sync.Mutex
}

func newReaderWorkerPool(db *sql.DB, numWorkers int) (*readerWorkerPool, error) {
	pool := new(readerWorkerPool)

	for range numWorkers {
		rw, err := newReaderWorker(db)
		if err != nil {
			pool.Close()
			return nil, err
		}
		pool.workers = append(pool.workers, rw)
	}

	return pool, nil
}

func (pool *readerWorkerPool) Submit(job any) {
	rw := pool.GetWorker()
	rw.Submit(job)
}

func (pool *readerWorkerPool) GetWorker() *readerWorker {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	rw := pool.workers[pool.next]
	pool.next = (pool.next + 1) % len(pool.workers)
	return rw
}

func (pool *readerWorkerPool) Close() {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	for _, rw := range pool.workers {
		rw.Close()
	}
}

type readerWorker struct {
	db    *sql.DB
	conn  *sql.Conn
	cache *Cache
	jobs  queue.Queue
	wg    sync.WaitGroup
	quit  chan struct{}
}

func newReaderWorker(db *sql.DB) (*readerWorker, error) {
	rw := &readerWorker{
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
		jobs: queue.NewQueue(),
		quit: make(chan struct{}),
	}

	if err := rw.acquireConn(); err != nil {
		return nil, err
	}

	rw.wg.Add(1)
	go rw.run()
	return rw, nil
}

func (rw *readerWorker) Submit(job any) {
	rw.jobs.Append(job)
}

func (rw *readerWorker) Close() {
	close(rw.quit)
	rw.wg.Wait()
	rw.cache.Close()
	_ = rw.conn.Close()
}

func (rw *readerWorker) getOrPrepare(ctx context.Context, key, sqlText string) (Lease, error) {
	if lease, ok := rw.cache.GetLease(key); ok {
		return lease, nil
	}

	ps, err := rw.conn.PrepareContext(ctx, sqlText)
	if err != nil && errors.Is(err, driver.ErrBadConn) {
		_ = rw.conn.Close()
		if err := rw.acquireConn(); err != nil {
			return Lease{}, err
		}
		ps, err = rw.conn.PrepareContext(ctx, sqlText)
	}
	if err != nil {
		return Lease{}, err
	}
	rw.cache.Put(key, ps)

	lease, ok := rw.cache.GetLease(key)
	if !ok {
		return Lease{}, errors.New("failed to acquire the prepared statement")
	}
	return lease, nil
}

func (rw *readerWorker) acquireConn() error {
	rw.cache.RetireAll()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := rw.db.Conn(ctx)
	if err != nil {
		return err
	}

	_, err = conn.ExecContext(ctx, `PRAGMA query_only = on`)
	if err != nil {
		return err
	}

	rw.conn = conn
	return nil
}

func (rw *readerWorker) run() {
	defer rw.wg.Done()

	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-rw.quit:
			return
		case <-rw.jobs.Signal():
			rw.jobs.Process(rw.processJob)
		case <-ticker.C:
			if !rw.jobs.Empty() {
				rw.jobs.Process(rw.processJob)
			}
		}
	}
}

func (rw *readerWorker) processJob(job any) {
	switch j := job.(type) {
	case *rowReadJob:
		rw.processRowReadJob(j)
	case *rowsReadJob:
		rw.processRowsReadJob(j)
	}
}

func (rw *readerWorker) processRowReadJob(j *rowReadJob) {
	if j == nil || j.Result == nil {
		return
	}
	if j.Ctx == nil {
		j.Result <- &rowReadResult{Row: nil, Err: errors.New("context is nil")}
		return
	}
	if err := j.Ctx.Err(); err != nil {
		j.Result <- &rowReadResult{Row: nil, Err: err}
		return
	}
	if j.Name == "" || j.SQLText == "" {
		j.Result <- &rowReadResult{Row: nil, Err: errors.New("invalid read job")}
		return
	}

	lease, err := rw.getOrPrepare(j.Ctx, j.Name, j.SQLText)
	if err != nil {
		j.Result <- &rowReadResult{Row: nil, Err: err}
		return
	}
	defer lease.Release()

	row := lease.Stmt.QueryRowContext(j.Ctx, j.Args...)
	if row == nil {
		j.Result <- &rowReadResult{Row: nil, Err: sql.ErrNoRows}
		return
	}

	if err := row.Err(); err != nil {
		if errors.Is(err, driver.ErrBadConn) {
			_ = rw.conn.Close()
			if err := rw.acquireConn(); err != nil {
				j.Result <- &rowReadResult{Row: nil, Err: err}
				return
			}

			lease, err = rw.getOrPrepare(j.Ctx, j.Name, j.SQLText)
			if err != nil {
				j.Result <- &rowReadResult{Row: nil, Err: err}
				return
			}
			defer lease.Release()

			row = lease.Stmt.QueryRowContext(j.Ctx, j.Args...)
		} else {
			j.Result <- &rowReadResult{Row: nil, Err: err}
			return
		}
	}
	if row == nil {
		j.Result <- &rowReadResult{Row: nil, Err: sql.ErrNoRows}
		return
	}

	j.Result <- &rowReadResult{Row: row, Err: nil}
}

func (rw *readerWorker) processRowsReadJob(j *rowsReadJob) {
	if j == nil || j.Result == nil {
		return
	}
	if j.Ctx == nil {
		j.Result <- &rowsReadResult{Rows: nil, Err: errors.New("context is nil")}
		return
	}
	if err := j.Ctx.Err(); err != nil {
		j.Result <- &rowsReadResult{Rows: nil, Err: err}
		return
	}
	if j.Name == "" || j.SQLText == "" {
		j.Result <- &rowsReadResult{Rows: nil, Err: errors.New("invalid read job")}
		return
	}

	lease, err := rw.getOrPrepare(j.Ctx, j.Name, j.SQLText)
	if err != nil {
		j.Result <- &rowsReadResult{Rows: nil, Err: err}
		return
	}
	defer lease.Release()

	rows, err := lease.Stmt.QueryContext(j.Ctx, j.Args...)
	if rows == nil {
		j.Result <- &rowsReadResult{Rows: nil, Err: sql.ErrNoRows}
		return
	}

	if err != nil {
		if errors.Is(err, driver.ErrBadConn) {
			_ = rw.conn.Close()
			if err := rw.acquireConn(); err != nil {
				j.Result <- &rowsReadResult{Rows: nil, Err: err}
				return
			}

			lease, err = rw.getOrPrepare(j.Ctx, j.Name, j.SQLText)
			if err != nil {
				j.Result <- &rowsReadResult{Rows: nil, Err: err}
				return
			}
			defer lease.Release()

			rows, err = lease.Stmt.QueryContext(j.Ctx, j.Args...)
		} else {
			j.Result <- &rowsReadResult{Rows: nil, Err: err}
			return
		}
	}
	if err != nil || rows == nil {
		j.Result <- &rowsReadResult{Rows: nil, Err: sql.ErrNoRows}
		return
	}

	j.Result <- &rowsReadResult{Rows: rows, Err: nil}
}
