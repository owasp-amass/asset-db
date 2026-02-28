// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"database/sql"
	"hash/fnv"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// CostFunc estimates "cache pressure" of an entry.
// Prepared-statement memory is driver/DB dependent; provide an estimate that correlates
// with pressure (e.g., SQL length + constant).
type CostFunc func(key string, stmt *sql.Stmt) int64

// Lease is a concurrency-safe handle to a statement.
// You MUST call Release() when done using Lease.Stmt.
type Lease struct {
	Stmt *sql.Stmt
	e    *entry
}

// Release decrements the in-flight count and closes the statement if it was retired
// and this was the last user.
func (l Lease) Release() {
	if l.e == nil {
		return
	}
	if atomic.AddInt32(&l.e.inflight, -1) == 0 && atomic.LoadUint32(&l.e.retired) == 1 {
		_ = l.e.stmt.Close()
	}
}

// CacheOptions configures the cache.
type CacheOptions struct {
	// Limits
	MaxBytes   int64 // 0 = unlimited bytes (not recommended)
	MaxEntries int   // always enforced (minimum 1)

	// Eviction scoring:
	// score = IdleWeight*idleSeconds + AgeWeight*ageSeconds - HitWeight*log1p(hits)
	// Higher score => evict sooner
	IdleWeight float64
	AgeWeight  float64
	HitWeight  float64

	// Optional hard TTLs: entries beyond these thresholds are treated as "very bad"
	// and evicted first (still safely: retired then close when inflight==0)
	IdleTTL time.Duration // based on now-lastHit
	AgeTTL  time.Duration // based on now-insertedAt

	// Performance tuning
	Shards  int // power-of-two recommended (16, 32, 64). Default 32
	SampleN int // candidates per eviction attempt. Default 64

	// Hooks
	CostFn CostFunc
	Now    func() time.Time

	// Randomness
	RandSeed int64 // default uses time.Now().UnixNano()
}

// Cache is a size-aware prepared statement cache.
// Eviction is safe with concurrent statement usage via retire+refcount (Lease).
type Cache struct {
	shards    []shard
	shardMask uint64

	maxBytes   int64
	maxEntries int

	idleWeight float64
	ageWeight  float64
	hitWeight  float64
	idleTTL    time.Duration
	ageTTL     time.Duration

	costFn CostFunc
	now    func() time.Time

	totalBytes   int64 // accessed via atomic
	totalEntries int64 // accessed via atomic

	sampleN int
	rngMu   sync.Mutex
	rng     *rand.Rand
}

type shard struct {
	mu sync.Mutex
	m  map[string]*entry
}

type entry struct {
	key        string
	stmt       *sql.Stmt
	cost       int64
	insertedAt time.Time

	lastHitUnix int64  // UnixNano; atomic
	hits        uint64 // atomic

	inflight int32  // atomic: active leases
	retired  uint32 // atomic: removed from map
}

// New constructs a cache with defaults suited to high insert rates.
func NewCache(opts CacheOptions) *Cache {
	shards := opts.Shards
	if shards <= 0 {
		shards = 32
	}
	// ensure power-of-two shard count
	if shards&(shards-1) != 0 {
		n := 1
		for n < shards {
			n <<= 1
		}
		shards = n
	}

	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 1
	}
	if opts.SampleN <= 0 {
		opts.SampleN = 64
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	costFn := opts.CostFn
	if costFn == nil {
		// default "pressure" estimate: key length + constant
		// if key is a hash, supply your own CostFn
		costFn = func(key string, _ *sql.Stmt) int64 { return int64(len(key)) + 512 }
	}

	seed := opts.RandSeed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}

	c := &Cache{
		shards:     make([]shard, shards),
		shardMask:  uint64(shards - 1),
		maxBytes:   opts.MaxBytes,
		maxEntries: opts.MaxEntries,

		idleWeight: opts.IdleWeight,
		ageWeight:  opts.AgeWeight,
		hitWeight:  opts.HitWeight,
		idleTTL:    opts.IdleTTL,
		ageTTL:     opts.AgeTTL,

		costFn:  costFn,
		now:     now,
		sampleN: opts.SampleN,
		rng:     rand.New(rand.NewSource(seed)),
	}

	for i := range c.shards {
		c.shards[i].m = make(map[string]*entry)
	}

	// default weights if caller left all 0:
	if c.idleWeight == 0 && c.ageWeight == 0 && c.hitWeight == 0 {
		c.idleWeight = 5.0
		c.ageWeight = 0.2
		c.hitWeight = 25.0
	}

	return c
}

// GetLease acquires a lease to a statement. Caller must Release().
// Returns false if not in cache.
func (c *Cache) GetLease(key string) (Lease, bool) {
	s := &c.shards[c.shardFor(key)]

	s.mu.Lock()
	e := s.m[key]
	if e == nil || atomic.LoadUint32(&e.retired) == 1 {
		s.mu.Unlock()
		return Lease{}, false
	}

	atomic.AddInt32(&e.inflight, 1)
	atomic.AddUint64(&e.hits, 1)
	atomic.StoreInt64(&e.lastHitUnix, c.now().UnixNano())
	stmt := e.stmt
	s.mu.Unlock()

	return Lease{Stmt: stmt, e: e}, true
}

// Put inserts or replaces a statement entry.
// If replacing, the old entry is retired (removed from map) and closed only when safe.
func (c *Cache) Put(key string, stmt *sql.Stmt) {
	now := c.now()

	ne := &entry{
		key:        key,
		stmt:       stmt,
		cost:       c.costFn(key, stmt),
		insertedAt: now,
	}
	atomic.StoreInt64(&ne.lastHitUnix, now.UnixNano())

	s := &c.shards[c.shardFor(key)]
	s.mu.Lock()

	if old := s.m[key]; old != nil {
		delete(s.m, key)
		atomic.StoreUint32(&old.retired, 1)

		atomic.AddInt64(&c.totalBytes, -old.cost)
		atomic.AddInt64(&c.totalEntries, -1)

		if atomic.LoadInt32(&old.inflight) == 0 {
			_ = old.stmt.Close()
		}
	}

	s.m[key] = ne
	atomic.AddInt64(&c.totalBytes, ne.cost)
	atomic.AddInt64(&c.totalEntries, 1)

	s.mu.Unlock()

	c.enforceLimits()
}

// Len returns approximate number of entries.
func (c *Cache) Len() int {
	return int(atomic.LoadInt64(&c.totalEntries))
}

// Bytes returns approximate total cost.
func (c *Cache) Bytes() int64 {
	return atomic.LoadInt64(&c.totalBytes)
}

// RetireAll removes all entries from the cache and marks them retired.
// Statements are closed immediately if no leases are in flight; otherwise they
// will close when the last Lease.Release() occurs.
func (c *Cache) RetireAll() {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		for k, e := range s.m {
			delete(s.m, k)
			atomic.StoreUint32(&e.retired, 1)

			atomic.AddInt64(&c.totalBytes, -e.cost)
			atomic.AddInt64(&c.totalEntries, -1)

			if atomic.LoadInt32(&e.inflight) == 0 {
				_ = e.stmt.Close()
			}
		}
		s.mu.Unlock()
	}
}

// Close retires and closes all statements when safe.
// Any in-flight leases will close their statements on Release().
func (c *Cache) Close() {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		for k, e := range s.m {
			delete(s.m, k)
			atomic.StoreUint32(&e.retired, 1)

			atomic.AddInt64(&c.totalBytes, -e.cost)
			atomic.AddInt64(&c.totalEntries, -1)

			if atomic.LoadInt32(&e.inflight) == 0 {
				_ = e.stmt.Close()
			}
		}
		s.mu.Unlock()
	}
}

func (c *Cache) enforceLimits() {
	// best-effort loop (no global lock); evicts until within limits or can't progress
	for {
		bytes := atomic.LoadInt64(&c.totalBytes)
		ents := atomic.LoadInt64(&c.totalEntries)

		overBytes := c.maxBytes > 0 && bytes > c.maxBytes
		overEnts := int(ents) > c.maxEntries

		if !overBytes && !overEnts {
			return
		}
		if !c.evictOne() {
			// could not evict (e.g., no candidates). stop
			return
		}
	}
}

// evictOne samples candidates and retires the "worst" by score.
// Returns true if an entry was retired.
func (c *Cache) evictOne() bool {
	now := c.now()

	type cand struct {
		si    int
		key   string
		e     *entry
		score float64
	}

	var worst *cand

	for i := 0; i < c.sampleN; i++ {
		si := int(c.randUint64() & c.shardMask)
		s := &c.shards[si]

		s.mu.Lock()
		var pick *entry
		if len(s.m) > 0 {
			n := int(c.randUint64() % uint64(len(s.m)))
			j := 0
			for _, e := range s.m {
				if j == n {
					pick = e
					break
				}
				j++
			}
		}

		if pick != nil && atomic.LoadUint32(&pick.retired) == 0 {
			sc := c.score(now, pick)
			cc := cand{si: si, key: pick.key, e: pick, score: sc}
			if worst == nil || cc.score > worst.score {
				tmp := cc
				worst = &tmp
			}
		}
		s.mu.Unlock()
	}

	if worst == nil {
		return false
	}

	// retire chosen candidate
	s := &c.shards[worst.si]
	s.mu.Lock()
	cur := s.m[worst.key]
	if cur == worst.e && cur != nil {
		delete(s.m, worst.key)
		atomic.StoreUint32(&cur.retired, 1)

		atomic.AddInt64(&c.totalBytes, -cur.cost)
		atomic.AddInt64(&c.totalEntries, -1)

		if atomic.LoadInt32(&cur.inflight) == 0 {
			_ = cur.stmt.Close()
		}
		s.mu.Unlock()
		return true
	}
	s.mu.Unlock()
	return false
}

// score computes eviction score. Higher score => evict sooner.
func (c *Cache) score(now time.Time, e *entry) float64 {
	age := now.Sub(e.insertedAt)
	ageSec := age.Seconds()

	lh := atomic.LoadInt64(&e.lastHitUnix)
	var idleSec float64
	if lh > 0 {
		idleSec = now.Sub(time.Unix(0, lh)).Seconds()
	} else {
		idleSec = ageSec
	}

	// hard TTLs: treat as "extremely bad" so they get evicted first
	if c.idleTTL > 0 && idleSec > c.idleTTL.Seconds() {
		return 1e18 + idleSec
	}
	if c.ageTTL > 0 && age > c.ageTTL {
		return 5e17 + ageSec
	}

	h := float64(atomic.LoadUint64(&e.hits))
	hot := math.Log1p(h)

	return c.idleWeight*idleSec + c.ageWeight*ageSec - c.hitWeight*hot
}

func (c *Cache) shardFor(key string) int {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum64() & c.shardMask)
}

func (c *Cache) randUint64() uint64 {
	c.rngMu.Lock()
	v := uint64(c.rng.Int63())
	c.rngMu.Unlock()
	return v
}
