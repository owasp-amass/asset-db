// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"
	"sync"
	"time"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// canonicalLocks serializes WithCanonicalLock callers that share a key within
// this process. The set of canonical keys is bounded in practice.
var canonicalLocks sync.Map // map[string]*sync.Mutex

func lockCanonical(key string) func() {
	v, _ := canonicalLocks.LoadOrStore(key, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// lockLabel labels the internal nodes that serialize canonical creation across
// processes. The leading underscore keeps it out of the asset label space.
const lockLabel = "_amass_canonical_lock"

// canonicalLockWait bounds how long acquiring the cross-process lock may block
// before the caller proceeds under the in-process lock alone.
const canonicalLockWait = 30 * time.Second

// lockConstraint ensures, once per process, the uniqueness constraint that
// makes the MERGE below an atomic get-or-create: without it two processes could
// each create a lock node for the same key and never serialize.
var lockConstraint sync.Once
var lockConstraintOK bool

func (r *NeoRepository) ensureLockConstraint(ctx context.Context) bool {
	lockConstraint.Do(func() {
		cctx, cancel := context.WithTimeout(ctx, canonicalLockWait)
		defer cancel()

		_, err := neo4jdb.ExecuteQuery(cctx, r.DB,
			"CREATE CONSTRAINT amass_canonical_lock_key IF NOT EXISTS "+
				"FOR (l:`"+lockLabel+"`) REQUIRE l.key IS UNIQUE",
			nil, neo4jdb.EagerResultTransformer, neo4jdb.ExecuteQueryWithDatabase(r.dbname))
		lockConstraintOK = err == nil
	})
	return lockConstraintOK
}

// WithCanonicalLock runs fn while holding an exclusive lock on canonicalKey: a
// per-key mutex within this process, and, across the processes sharing this
// database, a write lock on a lock node of label _amass_canonical_lock keyed by
// canonicalKey. The lock node is taken in an explicit transaction that stays
// open for fn's duration — Neo4j holds the node's write lock until the
// transaction ends — so concurrent engine sessions creating the same logical
// entity converge on one record instead of racing. fn's own database work runs
// on separate sessions and never touches the lock node, so it is not obstructed
// and cannot deadlock against the lock. If the lock cannot be taken (no
// constraint, a driver error, or the wait elapses), fn still runs under the
// in-process lock. An empty key runs fn without locking.
func (r *NeoRepository) WithCanonicalLock(ctx context.Context, canonicalKey string, fn func() error) error {
	if canonicalKey == "" {
		return fn()
	}

	unlock := lockCanonical(canonicalKey)
	defer unlock()

	if r.DB == nil || !r.ensureLockConstraint(ctx) {
		return fn()
	}

	session := r.DB.NewSession(ctx, neo4jdb.SessionConfig{
		DatabaseName: r.dbname,
		AccessMode:   neo4jdb.AccessModeWrite,
	})
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = session.Close(closeCtx)
	}()

	tx, err := session.BeginTransaction(ctx)
	if err != nil {
		return fn()
	}

	// Bound only the acquisition; once the node's write lock is held the
	// transaction stays open for fn's full duration.
	acqCtx, cancel := context.WithTimeout(ctx, canonicalLockWait)
	defer cancel()
	res, err := tx.Run(acqCtx, "MERGE (l:`"+lockLabel+"` {key: $key}) SET l.held_at = timestamp()",
		map[string]any{"key": canonicalKey})
	if err == nil {
		// Consume so the write — and therefore the lock — is actually taken.
		_, err = res.Consume(acqCtx)
	}
	if err != nil {
		rollback(tx)
		return fn()
	}

	// Release the lock only after fn has finished, by ending the transaction.
	fnErr := fn()
	commit(tx)
	return fnErr
}

// commit ends the lock transaction, releasing the node's write lock. A failed
// commit falls back to a rollback, which also releases the lock.
func commit(tx neo4jdb.ExplicitTransaction) {
	cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := tx.Commit(cctx); err != nil {
		rollback(tx)
	}
}

// rollback ends the lock transaction on a fresh context, so the lock is
// released even when the caller's context is already done.
func rollback(tx neo4jdb.ExplicitTransaction) {
	rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = tx.Rollback(rctx)
}
