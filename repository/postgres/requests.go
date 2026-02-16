// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type job interface {
	GetCtx() context.Context
	GetSQLText() string
	GetArgs() pgx.NamedArgs
	Done() chan error
	Wait() error
	// Methods for batching and decoding results:
	Queue(*pgx.Batch)
	Decode(pgx.BatchResults) error
	// Tx-mode that support interactive execution
	RunTx(pgx.Tx) error
}

func NewExecJob(ctx context.Context, sqlText string, args pgx.NamedArgs, callback func(tag pgconn.CommandTag) error) job {
	ch := make(chan error, 1)
	return &execJob{
		Ctx:      ctx,
		SQLText:  sqlText,
		Args:     args,
		Ch:       ch,
		Callback: callback,
	}
}

func NewRowJob(ctx context.Context, sqlText string, args pgx.NamedArgs, callback func(pgx.Row) error) job {
	ch := make(chan error, 1)
	return &rowJob{
		Ctx:      ctx,
		SQLText:  sqlText,
		Args:     args,
		Ch:       ch,
		Callback: callback,
	}
}

func NewRowsJob(ctx context.Context, sqlText string, args pgx.NamedArgs, callback func(pgx.Rows) error) job {
	ch := make(chan error, 1)
	return &rowsJob{
		Ctx:      ctx,
		SQLText:  sqlText,
		Args:     args,
		Ch:       ch,
		Callback: callback,
	}
}

type execJob struct {
	Ctx      context.Context
	SQLText  string
	Args     pgx.NamedArgs
	Ch       chan error
	Callback func(tag pgconn.CommandTag) error
}

func (w *execJob) GetCtx() context.Context {
	return w.Ctx
}

func (w *execJob) GetSQLText() string {
	return w.SQLText
}

func (w *execJob) GetArgs() pgx.NamedArgs {
	return w.Args
}

func (w *execJob) Done() chan error {
	return w.Ch
}

func (w *execJob) Wait() error {
	select {
	case err := <-w.Done():
		return err
	case <-w.Ctx.Done():
		return w.Ctx.Err()
	}
}

func (w *execJob) Queue(batch *pgx.Batch) {
	batch.Queue(w.SQLText, w.Args)
}

func (w *execJob) Decode(br pgx.BatchResults) error {
	tag, err := br.Exec()
	if err != nil {
		return wrapPgErr("batch decode", err)
	}

	if w.Callback != nil {
		return w.Callback(tag)
	}
	return nil
}

func (w *execJob) RunTx(tx pgx.Tx) error {
	tag, err := tx.Exec(w.Ctx, w.SQLText, w.Args)
	if err != nil {
		return wrapPgErr("tx exec", err)
	}
	if w.Callback != nil {
		if err := w.Callback(tag); err != nil {
			return fmt.Errorf("tx exec callback: %w", err)
		}
	}
	return nil
}

type rowJob struct {
	Ctx      context.Context
	SQLText  string
	Args     pgx.NamedArgs
	Ch       chan error
	Callback func(pgx.Row) error
}

func (r *rowJob) GetCtx() context.Context {
	return r.Ctx
}

func (r *rowJob) GetSQLText() string {
	return r.SQLText
}

func (r *rowJob) GetArgs() pgx.NamedArgs {
	return r.Args
}

func (r *rowJob) Done() chan error {
	return r.Ch
}

func (r *rowJob) Wait() error {
	select {
	case err := <-r.Done():
		return err
	case <-r.Ctx.Done():
		return r.Ctx.Err()
	}
}

func (r *rowJob) Queue(batch *pgx.Batch) {
	batch.Queue(r.SQLText, r.Args)
}

func (r *rowJob) Decode(br pgx.BatchResults) error {
	row := br.QueryRow()
	if r.Callback != nil {
		return r.Callback(row)
	}
	return row.Scan()
}

func (r *rowJob) RunTx(tx pgx.Tx) error {
	row := tx.QueryRow(r.Ctx, r.SQLText, r.Args)

	if r.Callback != nil {
		if err := r.Callback(row); err != nil {
			return wrapPgErr("tx queryrow callback", err)
		}
		return nil
	}

	return wrapPgErr("tx queryrow scan", row.Scan())
}

type rowsJob struct {
	Ctx      context.Context
	SQLText  string
	Args     pgx.NamedArgs
	Ch       chan error
	Callback func(pgx.Rows) error
}

func (r *rowsJob) GetCtx() context.Context {
	return r.Ctx
}

func (r *rowsJob) GetSQLText() string {
	return r.SQLText
}

func (r *rowsJob) GetArgs() pgx.NamedArgs {
	return r.Args
}

func (r *rowsJob) Done() chan error {
	return r.Ch
}

func (r *rowsJob) Wait() error {
	select {
	case err := <-r.Done():
		return err
	case <-r.Ctx.Done():
		return r.Ctx.Err()
	}
}

func (r *rowsJob) Queue(batch *pgx.Batch) {
	batch.Queue(r.SQLText, r.Args)
}

func (r *rowsJob) Decode(br pgx.BatchResults) error {
	rows, err := br.Query()
	if err != nil {
		return wrapPgErr("batch decode", err)
	}
	defer rows.Close()

	if r.Callback != nil {
		return r.Callback(rows)
	}
	return nil
}

func (r *rowsJob) RunTx(tx pgx.Tx) error {
	rows, err := tx.Query(r.Ctx, r.SQLText, r.Args)
	if err != nil {
		return wrapPgErr("tx query", err)
	}
	defer rows.Close()

	if r.Callback != nil {
		if err := r.Callback(rows); err != nil {
			return wrapPgErr("tx rows callback", err)
		}
	}
	return nil
}

func wrapPgErr(prefix string, err error) error {
	if err == nil {
		return nil
	}
	// Surface pgconn.PgError where possible.
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return fmt.Errorf("%s (pg): %s (SQLSTATE %s): %w", prefix, pgErr.Message, pgErr.Code, err)
	}
	return fmt.Errorf("%s: %w", prefix, err)
}
