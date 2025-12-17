// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync"
	"time"

	"github.com/caffix/queue"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type job interface {
	GetCtx() context.Context
	GetName() string
	GetSQLText() string
	GetArgs() []any
}

type execJob struct {
	Ctx     context.Context
	Name    string
	SQLText string
	Args    []any
	Result  chan error
}

func (w *execJob) GetCtx() context.Context {
	return w.Ctx
}

func (w *execJob) GetName() string {
	return w.Name
}

func (w *execJob) GetSQLText() string {
	return w.SQLText
}

func (w *execJob) GetArgs() []any {
	return w.Args
}

type rowResult struct {
	Row *sql.Row
	Err error
}

type rowJob struct {
	Ctx     context.Context
	Name    string
	SQLText string
	Args    []any
	Result  chan *rowResult
}

func (r *rowJob) GetCtx() context.Context {
	return r.Ctx
}

func (r *rowJob) GetName() string {
	return r.Name
}

func (r *rowJob) GetSQLText() string {
	return r.SQLText
}

func (r *rowJob) GetArgs() []any {
	return r.Args
}

type rowsResult struct {
	Rows *sql.Rows
	Err  error
}

type rowsJob struct {
	Ctx     context.Context
	Name    string
	SQLText string
	Args    []any
	Result  chan *rowsResult
}

func (r *rowsJob) GetCtx() context.Context {
	return r.Ctx
}

func (r *rowsJob) GetName() string {
	return r.Name
}

func (r *rowsJob) GetSQLText() string {
	return r.SQLText
}

func (r *rowsJob) GetArgs() []any {
	return r.Args
}

type worker struct {
	db            *sql.DB
	conn          *sql.Conn
	stmts         map[string]*sql.Stmt
	jobs          queue.Queue
	batchSize     int
	batchDuration time.Duration
	wg            sync.WaitGroup
	quit          chan struct{}
}

type workerPool struct {
	workers []*worker
	next    int
	mu      sync.Mutex
}

func newWorkerPool(db *sql.DB, numWorkers, batchSize int, batchDuration time.Duration) (*workerPool, error) {
	pool := new(workerPool)
	for range numWorkers {
		rw, err := newWorker(db, batchSize, batchDuration)
		if err != nil {
			pool.Close()
			return nil, err
		}
		pool.workers = append(pool.workers, rw)
	}

	return pool, nil
}

func (pool *workerPool) Submit(job any) {
	rw := pool.GetWorker()
	rw.Submit(job)
}

func (pool *workerPool) GetWorker() *worker {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	rw := pool.workers[pool.next]
	pool.next = (pool.next + 1) % len(pool.workers)
	return rw
}

func (pool *workerPool) Close() {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	for _, rw := range pool.workers {
		rw.Close()
	}
}

func newWorker(db *sql.DB, batchSize int, batchDuration time.Duration) (*worker, error) {
	w := &worker{
		db:            db,
		stmts:         make(map[string]*sql.Stmt),
		jobs:          queue.NewQueue(),
		batchSize:     batchSize,
		batchDuration: batchDuration,
		quit:          make(chan struct{}),
	}

	if err := w.acquireConn(); err != nil {
		return nil, err
	}

	w.wg.Add(1)
	go w.run()
	return w, nil
}

func (w *worker) Submit(job any) {
	w.jobs.Append(job)
}

func (w *worker) Close() {
	close(w.quit)
	w.wg.Wait()
	w.closeStmts()
	_ = w.conn.Close()
}

func (w *worker) closeStmts() {
	for _, st := range w.stmts {
		_ = st.Close()
	}
	w.stmts = make(map[string]*sql.Stmt)
}

func (w *worker) getOrPrepare(ctx context.Context, key, sqlText string) (*sql.Stmt, error) {
	st, found := w.stmts[key]
	if found && st != nil {
		return st, nil
	}

	ps, err := w.conn.PrepareContext(ctx, sqlText)
	if err != nil && errors.Is(err, driver.ErrBadConn) {
		_ = w.conn.Close()
		if err := w.acquireConn(); err != nil {
			return nil, err
		}
		ps, err = w.conn.PrepareContext(ctx, sqlText)
	}
	if err != nil {
		return nil, err
	}

	w.stmts[key] = ps
	return ps, nil
}

func (w *worker) acquireConn() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := w.db.Conn(ctx)
	if err != nil {
		return err
	}

	w.conn = conn
	w.closeStmts()
	return nil
}

func (w *worker) run() {
	defer w.wg.Done()

	batchdur := time.NewTicker(w.batchDuration)
	defer batchdur.Stop()

	check := time.NewTicker(5 * time.Millisecond)
	defer check.Stop()

	var txlist []job
	commit := func() {
		var err error
		txlist, err = w.flushJobs(txlist)
		for err != nil && len(txlist) > 0 {
			txlist, err = w.flushJobs(txlist)
		}
	}

	queueCheck := func() {
		for !w.jobs.Empty() {
			j, ok := w.jobs.Next()
			if !ok || j == nil {
				continue
			}

			var wj job
			switch v := j.(type) {
			case *execJob:
				if v.Result == nil {
					continue
				}
				wj = v
			case *rowJob:
				if v.Result == nil {
					continue
				}
				wj = v
			case *rowsJob:
				if v.Result == nil {
					continue
				}
				wj = v
			default:
				continue
			}

			if wj.GetCtx() == nil {
				errToJob(wj, errors.New("context is nil"))
				continue
			}

			if err := wj.GetCtx().Err(); err != nil {
				errToJob(wj, err)
				continue
			}

			if wj.GetName() == "" || wj.GetSQLText() == "" {
				errToJob(wj, errors.New("invalid write job"))
				continue
			}

			txlist = append(txlist, wj)
			if len(txlist) >= w.batchSize {
				commit()
				return
			}
		}
	}

	for {
		select {
		case <-w.quit:
			for !w.jobs.Empty() {
				queueCheck()
			}
			commit()
			return
		case <-batchdur.C:
			queueCheck()
			commit()
		case <-w.jobs.Signal():
			queueCheck()
		}
	}
}

func (w *worker) flushJobs(jobs []job) ([]job, error) {
	if len(jobs) == 0 {
		return []job{}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := w.conn.BeginTx(ctx, nil)
	if err != nil {
		if errors.Is(err, driver.ErrBadConn) {
			_ = w.conn.Close()
			if err := w.acquireConn(); err != nil {
				return jobs, err
			}
			tx, err = w.conn.BeginTx(ctx, nil)
		} else {
			return jobs, err
		}
	}
	if err != nil {
		return jobs, err
	}
	defer func() { _ = tx.Rollback() }()

	var failed bool
	var goodjobs []job
	var jobResults []any
	for i, job := range jobs {
		if err := job.GetCtx().Err(); err != nil {
			errToJob(job, err)
			continue
		}

		stmt, err := w.getOrPrepare(job.GetCtx(), job.GetName(), job.GetSQLText())
		if err != nil {
			errToJob(job, err)
			goodjobs = append(goodjobs, jobs[i+1:]...)
			failed = true
			break
		}

		switch v := job.(type) {
		case *execJob:
			_, err := tx.StmtContext(v.Ctx, stmt).ExecContext(v.Ctx, v.Args...)
			if err != nil {
				errToJob(job, err)
				goodjobs = append(goodjobs, jobs[i+1:]...)
				failed = true
				break
			}
			jobResults = append(jobResults, nil)
		case *rowJob:
			row := tx.StmtContext(v.Ctx, stmt).QueryRowContext(v.Ctx, v.Args...)
			jobResults = append(jobResults, &rowResult{Row: row, Err: nil})
		case *rowsJob:
			rows, err := tx.StmtContext(v.Ctx, stmt).QueryContext(v.Ctx, v.Args...)
			if err != nil {
				errToJob(job, err)
				goodjobs = append(goodjobs, jobs[i+1:]...)
				failed = true
				break
			}
			jobResults = append(jobResults, &rowsResult{Rows: rows, Err: nil})
		}

		goodjobs = append(goodjobs, job)
	}

	if !failed {
		if err := tx.Commit(); err == nil {
			returnJobResults(goodjobs, jobResults)
			return []job{}, nil
		}
	}
	return goodjobs, errors.New("transaction failed")
}

func errToJob(j job, err error) {
	switch v := j.(type) {
	case *execJob:
		v.Result <- err
	case *rowJob:
		v.Result <- &rowResult{Row: nil, Err: err}
	case *rowsJob:
		v.Result <- &rowsResult{Rows: nil, Err: err}
	}
}

func returnJobResults(jobs []job, results []any) {
	for i, j := range jobs {
		switch v := j.(type) {
		case *execJob:
			if res, ok := results[i].(error); ok {
				v.Result <- res
			} else {
				v.Result <- errors.New("invalid result type")
			}
		case *rowJob:
			if res, ok := results[i].(*rowResult); ok {
				v.Result <- res
			} else {
				v.Result <- &rowResult{Row: nil, Err: errors.New("invalid result type")}
			}
		case *rowsJob:
			if res, ok := results[i].(*rowsResult); ok {
				v.Result <- res
			} else {
				v.Result <- &rowsResult{Rows: nil, Err: errors.New("invalid result type")}
			}
		}
	}
}
