// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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

	check := time.NewTicker(10 * time.Millisecond)
	defer check.Stop()

	var txlist []*writeJob
	commit := func() {
		var err error
		txlist, err = ww.flushJobs(txlist)
		for err != nil && len(txlist) > 0 {
			txlist, err = ww.flushJobs(txlist)
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
				commit()
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
			commit()
			return
		case <-batchdur.C:
			queueCheck()
			commit()
		case <-ww.jobs.Signal():
			queueCheck()
		}
	}
}

func (ww *writeWorker) flushJobs(jobs []*writeJob) ([]*writeJob, error) {
	if len(jobs) == 0 {
		return []*writeJob{}, nil
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
		} else {
			errToJobs(jobs, err)
			return []*writeJob{}, nil
		}
	}

	if err != nil {
		errToJobs(jobs, err)
		return []*writeJob{}, nil
	}
	defer func() { _ = tx.Rollback() }()

	var failed bool
	var goodjobs []*writeJob
	for i, job := range jobs {
		if err := job.Ctx.Err(); err != nil {
			job.Result <- err
			continue
		}

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

	if !failed {
		if err := tx.Commit(); err == nil {
			errToJobs(goodjobs, nil)
			return []*writeJob{}, nil
		}
	}
	return goodjobs, errors.New("transaction failed")
}

func errToJobs(jobs []*writeJob, err error) {
	for _, job := range jobs {
		job.Result <- err
	}
}
