// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/stretchr/testify/assert"
)

// TestEngineWorkload times the reads and writes an enumeration makes when
// it revisits stored names: find each name, read its sources and DNS
// edges and their targets, and store the name, a source and an edge
// again. Set ASSETDB_POSTGRES_WORKLOAD_DSN to an empty database to run it.
func TestEngineWorkload(t *testing.T) {
	dsn := os.Getenv("ASSETDB_POSTGRES_WORKLOAD_DSN")
	if dsn == "" {
		t.Skip("ASSETDB_POSTGRES_WORKLOAD_DSN is not set")
	}

	names, workers := 2000, 32
	if v, err := strconv.Atoi(os.Getenv("ASSETDB_WORKLOAD_NAMES")); err == nil && v > 0 {
		names = v
	}

	repo, err := New("postgres", dsn)
	if !assert.NoError(t, err, "open the workload database") {
		return
	}

	defer func() { _ = repo.Close() }()

	ctx := context.Background()
	src := &general.SourceProperty{Source: "workload", Confidence: 100}
	since := time.Now().Add(-time.Hour)
	lat := newLatencies()

	// Store the names, their addresses, A records and sources, as a first
	// enumeration would.
	start := time.Now()
	run(names, workers, func(i int) {
		fqdn, err := timed(lat, "CreateAsset", func() (*dbt.Entity, error) {
			return repo.CreateAsset(ctx, &oamdns.FQDN{Name: fmt.Sprintf("host%d.workload.example", i)})
		})
		if err != nil {
			t.Errorf("store a name: %v", err)
			return
		}

		addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		ip, err := timed(lat, "CreateAsset", func() (*dbt.Entity, error) {
			return repo.CreateAsset(ctx, &oamnet.IPAddress{Address: addr, Type: "IPv4"})
		})
		if err != nil {
			t.Errorf("store an address: %v", err)
			return
		}

		if _, err := timed(lat, "CreateEntityProperty", func() (*dbt.EntityTag, error) {
			return repo.CreateEntityProperty(ctx, fqdn, src)
		}); err != nil {
			t.Errorf("store a source: %v", err)
		}
		if _, err := timed(lat, "CreateEdge", func() (*dbt.Edge, error) {
			return repo.CreateEdge(ctx, aRecord(fqdn, ip))
		}); err != nil {
			t.Errorf("store an edge: %v", err)
		}
	})
	t.Logf("store %d names with %d workers: %s", names, workers, time.Since(start).Round(time.Millisecond))
	lat.log(t)

	// Revisit every name, as a second enumeration within the TTL would.
	lat = newLatencies()
	start = time.Now()
	run(names, workers, func(i int) {
		name := fmt.Sprintf("host%d.workload.example", i)
		ents, err := timed(lat, "FindEntitiesByContent", func() ([]*dbt.Entity, error) {
			return repo.FindEntitiesByContent(ctx, oam.FQDN, time.Time{}, 1, dbt.ContentFilters{"name": name})
		})
		if err != nil || len(ents) == 0 {
			t.Errorf("find %s: %v", name, err)
			return
		}

		fqdn := ents[0]
		_, _ = timed(lat, "FindEntityTags", func() ([]*dbt.EntityTag, error) {
			return repo.FindEntityTags(ctx, fqdn, since, "source")
		})
		edges, err := timed(lat, "OutgoingEdges", func() ([]*dbt.Edge, error) {
			return repo.OutgoingEdges(ctx, fqdn, since, "dns_record")
		})
		if err != nil {
			t.Errorf("edges of %s: %v", name, err)
			return
		}

		for _, e := range edges {
			ip, err := timed(lat, "FindEntityById", func() (*dbt.Entity, error) {
				return repo.FindEntityById(ctx, e.ToEntity.ID)
			})
			if err != nil {
				t.Errorf("edge target: %v", err)
				continue
			}

			_, _ = timed(lat, "IncomingEdges", func() ([]*dbt.Edge, error) {
				return repo.IncomingEdges(ctx, ip, since, "dns_record")
			})
			if _, err := timed(lat, "CreateEdge", func() (*dbt.Edge, error) {
				return repo.CreateEdge(ctx, aRecord(fqdn, ip))
			}); err != nil {
				t.Errorf("store the edge again: %v", err)
			}
		}

		if _, err := timed(lat, "CreateAsset", func() (*dbt.Entity, error) {
			return repo.CreateAsset(ctx, &oamdns.FQDN{Name: name})
		}); err != nil {
			t.Errorf("store %s again: %v", name, err)
		}
		if _, err := timed(lat, "CreateEntityProperty", func() (*dbt.EntityTag, error) {
			return repo.CreateEntityProperty(ctx, fqdn, src)
		}); err != nil {
			t.Errorf("store the source again: %v", err)
		}
	})
	t.Logf("revisit %d names with %d workers: %s", names, workers, time.Since(start).Round(time.Millisecond))
	lat.log(t)
}

func aRecord(fqdn, ip *dbt.Entity) *dbt.Edge {
	return &dbt.Edge{
		Relation: &oamdns.BasicDNSRelation{Name: "dns_record",
			Header: oamdns.RRHeader{RRType: 1, Class: 1, TTL: 300}},
		FromEntity: fqdn,
		ToEntity:   ip,
	}
}

// run calls f for 0..n-1 from workers goroutines.
func run(n, workers int, f func(int)) {
	next := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				f(i)
			}
		}()
	}

	for i := range n {
		next <- i
	}

	close(next)
	wg.Wait()
}

type latencies struct {
	mu  sync.Mutex
	ops map[string][]time.Duration
}

func newLatencies() *latencies { return &latencies{ops: map[string][]time.Duration{}} }

func timed[T any](l *latencies, op string, f func() (T, error)) (T, error) {
	start := time.Now()
	v, err := f()
	d := time.Since(start)

	l.mu.Lock()
	l.ops[op] = append(l.ops[op], d)
	l.mu.Unlock()
	return v, err
}

func (l *latencies) log(t *testing.T) {
	ops := make([]string, 0, len(l.ops))
	for op := range l.ops {
		ops = append(ops, op)
	}

	sort.Strings(ops)

	var b strings.Builder
	for _, op := range ops {
		ds := l.ops[op]
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })

		var sum time.Duration
		for _, d := range ds {
			sum += d
		}

		fmt.Fprintf(&b, "\n  %-22s n=%-6d mean=%-9s p50=%-9s p99=%s", op, len(ds),
			(sum / time.Duration(len(ds))).Round(time.Microsecond), ds[len(ds)/2].Round(time.Microsecond),
			ds[len(ds)*99/100].Round(time.Microsecond))
	}

	t.Log(b.String())
}
