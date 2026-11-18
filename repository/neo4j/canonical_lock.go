// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"
	"sync"
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

// WithCanonicalLock runs fn while holding a per-key mutex, serializing callers
// that share canonicalKey within this process. Cross-process serialization for
// Neo4j (via a MERGE'd lock node) is a possible future addition; the in-process
// lock covers the dominant single-process case. An empty key runs fn without
// locking.
func (r *NeoRepository) WithCanonicalLock(ctx context.Context, canonicalKey string, fn func() error) error {
	if canonicalKey == "" {
		return fn()
	}

	unlock := lockCanonical(canonicalKey)
	defer unlock()

	return fn()
}
