// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/caffix/queue"
	_ "github.com/mattn/go-sqlite3"
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
	stmts         map[string]*sql.Stmt
	jobs          queue.Queue
	batchSize     int
	batchDuration time.Duration
	wg            sync.WaitGroup
	quit          chan struct{}
}

func newWriteWorker(db *sql.DB, batchSize int, batchDuration time.Duration) (*writeWorker, error) {
	ww := &writeWorker{
		db:            db,
		stmts:         make(map[string]*sql.Stmt),
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

	for _, st := range ww.stmts {
		_ = st.Close()
	}
	ww.stmts = nil
}

func (ww *writeWorker) closeStmts() {
	for _, st := range ww.stmts {
		_ = st.Close()
	}
	ww.stmts = make(map[string]*sql.Stmt)
}

func (ww *writeWorker) getOrPrepare(ctx context.Context, key, sqlText string) (*sql.Stmt, error) {
	st := ww.stmts[key]
	if st != nil {
		return st, nil
	}

	ps, err := ww.conn.PrepareContext(ctx, sqlText)
	if err != nil {
		return nil, err
	}

	ww.stmts[key] = ps
	return ps, nil
}

func (ww *writeWorker) acquireConn() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := ww.db.Conn(ctx)
	if err != nil {
		return err
	}

	ww.conn = conn
	ww.closeStmts()
	return nil
}

func (ww *writeWorker) run() {
	defer ww.wg.Done()

	batchdur := time.NewTicker(ww.batchDuration)
	defer batchdur.Stop()

	check := time.NewTicker(250 * time.Millisecond)
	defer check.Stop()

	var jobs []*writeJob

	errToJobs := func(err error) {
		for _, job := range jobs {
			job.Result <- err
		}
		jobs = jobs[:0]
	}

	commit := func() {
		if len(jobs) == 0 {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		tx, err := ww.conn.BeginTx(ctx, nil)
		if err != nil {
			if errors.Is(err, driver.ErrBadConn) {
				_ = ww.conn.Close()
				if err := ww.acquireConn(); err != nil {
					return
				}
				tx, err = ww.conn.BeginTx(ctx, nil)
			} else {
				errToJobs(err)
				return
			}
		}
		if err != nil {
			errToJobs(err)
			return
		}
		defer func() { _ = tx.Rollback() }()

		var failed bool
		var goodjobs []*writeJob
		for i, job := range jobs {
			stmt, err := ww.getOrPrepare(job.Ctx, job.Name, job.SQLText)
			if err != nil {
				job.Result <- err
				goodjobs = append(goodjobs, jobs[i+1:]...)
				failed = true
				break
			}

			if _, err = tx.StmtContext(job.Ctx, stmt).Exec(job.Args...); err != nil {
				job.Result <- err
				goodjobs = append(goodjobs, jobs[i+1:]...)
				failed = true
				break
			}

			goodjobs = append(goodjobs, job)
		}
		if failed {
			jobs = goodjobs
			return
		}
		if err := tx.Commit(); err != nil {
			errToJobs(err)
			return
		}

		errToJobs(nil)
	}

	queueCheck := func() {
		ww.jobs.Process(func(job any) {
			if j, valid := job.(*writeJob); valid {
				jobs = append(jobs, j)
			}
		})
		if len(jobs) >= ww.batchSize {
			commit()
		}
	}

	for {
		select {
		case <-ww.quit:
			commit()
			return
		case <-batchdur.C:
			commit()
		case <-ww.jobs.Signal():
			queueCheck()
		case <-check.C:
			queueCheck()
		}
	}
}

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
	stmts map[string]*sql.Stmt
	jobs  queue.Queue
	wg    sync.WaitGroup
	quit  chan struct{}
}

func newReaderWorker(db *sql.DB) (*readerWorker, error) {
	rw := &readerWorker{
		db:    db,
		stmts: make(map[string]*sql.Stmt),
		jobs:  queue.NewQueue(),
		quit:  make(chan struct{}),
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
	rw.closeStmts()
	_ = rw.conn.Close()
}

func (rw *readerWorker) closeStmts() {
	for _, st := range rw.stmts {
		_ = st.Close()
	}
	rw.stmts = make(map[string]*sql.Stmt)
}

func (rw *readerWorker) getOrPrepare(ctx context.Context, key, sqlText string) (*sql.Stmt, error) {
	st := rw.stmts[key]
	if st != nil {
		return st, nil
	}

	ps, err := rw.conn.PrepareContext(ctx, sqlText)
	if err != nil && errors.Is(err, driver.ErrBadConn) {
		_ = rw.conn.Close()
		if err := rw.acquireConn(); err != nil {
			return nil, err
		}
		ps, err = rw.conn.PrepareContext(ctx, sqlText)
	}
	if err != nil {
		return nil, err
	}

	rw.stmts[key] = ps
	return ps, nil
}

func (rw *readerWorker) acquireConn() error {
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
	rw.closeStmts()
	return nil
}

func (rw *readerWorker) run() {
	defer rw.wg.Done()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-rw.quit:
			return
		case <-rw.jobs.Signal():
			rw.jobs.Process(rw.processJob)
		case <-ticker.C:
			rw.jobs.Process(rw.processJob)
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
	stmt, err := rw.getOrPrepare(j.Ctx, j.Name, j.SQLText)
	if err != nil {
		j.Result <- &rowReadResult{Row: nil, Err: err}
		return
	}

	row := stmt.QueryRowContext(j.Ctx, j.Args...)
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
			row = stmt.QueryRowContext(j.Ctx, j.Args...)
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
	stmt, err := rw.getOrPrepare(j.Ctx, j.Name, j.SQLText)
	if err != nil {
		j.Result <- &rowsReadResult{Rows: nil, Err: err}
		return
	}

	rows, err := stmt.QueryContext(j.Ctx, j.Args...)
	if err != nil {
		if errors.Is(err, driver.ErrBadConn) {
			_ = rw.conn.Close()
			if err := rw.acquireConn(); err != nil {
				j.Result <- &rowsReadResult{Rows: nil, Err: err}
				return
			}
			rows, err = stmt.QueryContext(j.Ctx, j.Args...)
		} else {
			j.Result <- &rowsReadResult{Rows: nil, Err: err}
			return
		}
	}

	j.Result <- &rowsReadResult{Rows: rows, Err: err}
}

// ------------------------------ Scan Utilities ------------------------------

// parseTimestamp converts a *string timestamp into *time.Time (RFC3339 or SQLite
// default format). If parsing fails, returns nil (non-fatal for presentation purposes).
func parseTimestamp(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}

	str := strings.TrimSpace(s)
	if str == "" {
		return time.Time{}, nil
	}

	// Try SQLite's default (YYYY-MM-DD HH:MM:SS.SSS) then RFC3339
	layouts := []string{"2006-01-02T15:04:05Z07:00", time.RFC3339Nano,
		"2006-01-02 15:04:05.000", time.RFC3339, "2006-01-02 15:04:05",
	}

	for _, l := range layouts {
		if t, err := time.Parse(l, str); err == nil {
			return t, nil
		}
	}

	return time.Time{}, nil
}
