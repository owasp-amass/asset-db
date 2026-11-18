// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"sync"
	"time"
)

// canonicalLocks serializes WithCanonicalLock callers that share a key within
// this process. The map holds one mutex per distinct key seen; the set of
// canonical keys (organization names and the like) is bounded in practice.
var canonicalLocks sync.Map // map[string]*sync.Mutex

// lockCanonical acquires the in-process mutex for key and returns its unlock.
func lockCanonical(key string) func() {
	v, _ := canonicalLocks.LoadOrStore(key, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// advisoryLockWait bounds how long acquiring the cross-process advisory lock
// may block before the caller proceeds under the in-process lock alone.
const advisoryLockWait = 30 * time.Second

// WithCanonicalLock runs fn while holding an exclusive lock on canonicalKey: a
// per-key mutex within this process, and a PostgreSQL session advisory lock
// across the processes sharing this database, so concurrent engine sessions
// creating the same logical entity converge on one record instead of racing.
// The advisory lock is taken on a dedicated connection so fn's own database
// work (on the query and worker pools) runs unobstructed inside it. If the
// advisory lock cannot be taken, fn still runs under the in-process lock.
func (r *PostgresRepository) WithCanonicalLock(ctx context.Context, canonicalKey string, fn func() error) error {
	if canonicalKey == "" {
		return fn()
	}

	unlock := lockCanonical(canonicalKey)
	defer unlock()

	if r.lockDB == nil {
		return fn()
	}

	conn, err := r.lockDB.Conn(ctx)
	if err != nil {
		return fn()
	}
	defer func() { _ = conn.Close() }()

	lockCtx, cancel := context.WithTimeout(ctx, advisoryLockWait)
	defer cancel()
	if _, err := conn.ExecContext(lockCtx, "SELECT pg_advisory_lock(hashtext($1)::int8)", canonicalKey); err != nil {
		return fn()
	}
	defer func() {
		// Release on a fresh context so the unlock still runs when ctx is done.
		uctx, ucancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ucancel()
		_, _ = conn.ExecContext(uctx, "SELECT pg_advisory_unlock(hashtext($1)::int8)", canonicalKey)
	}()

	return fn()
}
