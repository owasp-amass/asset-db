// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"time"

	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	"github.com/owasp-amass/asset-db/types"
)

// WorkQueue is implemented by repositories that keep work queues: items of
// work, each named by a key unique in its queue and of a kind, that the
// tools sharing the database claim, lease and finish, so each item is
// worked on by one owner at a time.
type WorkQueue interface {
	// EnqueueWork puts keys of the kind in the queue as queued work. A key
	// already in the queue keeps its place but returns to queued, whatever
	// its state, so a caller that must not repeat work checks HasWork first.
	EnqueueWork(ctx context.Context, queue, kind string, keys ...string) error
	// HasWork returns those of keys that are in the queue, in any state.
	HasWork(ctx context.Context, queue string, keys ...string) (map[string]bool, error)
	// ClaimWork leases to owner up to n of the oldest items of the kind that
	// are queued or whose lease has expired, and returns their keys, oldest
	// first. A ttl of 0 leases them until they are acked or released.
	ClaimWork(ctx context.Context, queue, kind, owner string, n int, ttl time.Duration) ([]string, error)
	// RenewWork extends every lease owner holds in the queue to ttl from now
	// (0: until acked or released) and returns how many it extended.
	RenewWork(ctx context.Context, queue, owner string, ttl time.Duration) (int64, error)
	// AckWork marks an item done. Given an owner, it marks only an item the
	// owner leases, and returns types.ErrWorkNotLeased otherwise.
	AckWork(ctx context.Context, queue, key, owner string) error
	// ReleaseWork returns a leased item to queued; given an owner, only an
	// item the owner leases. Releasing an item not leased does nothing.
	ReleaseWork(ctx context.Context, queue, key, owner string) error
	// CountWork counts the queue's items of the kind, or of every kind when
	// kind is empty, in each state.
	CountWork(ctx context.Context, queue, kind string) (types.WorkCounts, error)
	// DeleteQueue removes every item of the queue.
	DeleteQueue(ctx context.Context, queue string) error
}

var (
	_ WorkQueue = (*postgres.PostgresRepository)(nil)
	_ WorkQueue = (*sqlite3.SqliteRepository)(nil)
)
