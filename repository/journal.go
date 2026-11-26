// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	"github.com/owasp-amass/asset-db/types"
)

// JournalStore is implemented by repositories that keep the journal: the
// append-only log the tools sharing the database coordinate through
// (types.JournalRecord).
type JournalStore interface {
	// AppendJournal appends a record and returns it with its sequence
	// number and time.
	AppendJournal(ctx context.Context, rec *types.JournalRecord) (*types.JournalRecord, error)
	// ReadJournal returns the topic's records after the sequence number
	// after (all when 0), in order, at most limit (all when 0).
	ReadJournal(ctx context.Context, topic string, after int64, limit int) ([]*types.JournalRecord, error)
	// LatestJournal returns the topic's newest record with the key, or an
	// error when it has none.
	LatestJournal(ctx context.Context, topic, key string) (*types.JournalRecord, error)
}

// LeaseStore is implemented by repositories that keep leases: named work
// one holder at a time may do (types.Lease).
type LeaseStore interface {
	// AcquireLease gives the lease to holder for ttl when it is free,
	// expired or already the holder's (which renews it), and reports
	// whether it did; otherwise it returns the lease as another holds it.
	AcquireLease(ctx context.Context, name, holder string, ttl time.Duration,
		data json.RawMessage) (*types.Lease, bool, error)
	// ReleaseLease frees a lease the holder holds; releasing one it does
	// not hold does nothing.
	ReleaseLease(ctx context.Context, name, holder string) error
	// FindLease returns a lease that has not expired, or an error.
	FindLease(ctx context.Context, name string) (*types.Lease, error)
}

var (
	_ JournalStore = (*postgres.PostgresRepository)(nil)
	_ JournalStore = (*sqlite3.SqliteRepository)(nil)
	_ LeaseStore   = (*postgres.PostgresRepository)(nil)
	_ LeaseStore   = (*sqlite3.SqliteRepository)(nil)
)
