// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// seenSinceSetting is the PostgreSQL setting the touch_guard trigger reads:
// when a row's last-seen time is at or after it, a sighting that brings
// nothing new is not written again until touch_window() has passed.
const seenSinceSetting = "amass.seen_since"

// connSettings holds settings applied to every connection the writer uses,
// including connections the pool opens later.
type connSettings struct {
	mu      sync.Mutex
	version uint64
	values  map[string]string
	applied sync.Map // *pgx.Conn -> the version applied to it
}

func newConnSettings() *connSettings {
	return &connSettings{values: map[string]string{}}
}

func (s *connSettings) set(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.values[name] = value
	s.version++
}

// prepare is the pool's PrepareConn hook: it brings a connection's settings
// up to date before the connection is used, and costs nothing when they are.
func (s *connSettings) prepare(ctx context.Context, conn *pgx.Conn) (bool, error) {
	s.mu.Lock()
	version := s.version
	values := make(map[string]string, len(s.values))
	for k, v := range s.values {
		values[k] = v
	}

	s.mu.Unlock()

	if v, ok := s.applied.Load(conn); ok && v.(uint64) == version {
		return true, nil
	}
	for k, v := range values {
		if _, err := conn.Exec(ctx, "SELECT set_config($1, $2, false)", k, v); err != nil {
			// discard the connection rather than write without the setting
			return false, nil
		}
	}

	s.applied.Store(conn, version)
	return true, nil
}

// forget is the pool's BeforeClose hook.
func (s *connSettings) forget(conn *pgx.Conn) {
	s.applied.Delete(conn)
}

// SetSeenSince implements repository.SeenSince. Writes made after the call
// belong to an enumeration that started at start: an asset, edge or tag last
// seen before start records this sighting, and one already seen since start
// keeps its last-seen time while nothing about it changes, for up to
// touch_window(). A zero start records every sighting again.
func (pr *PostgresRepository) SetSeenSince(start time.Time) {
	if pr == nil || pr.wset == nil {
		return
	}

	value := ""
	if !start.IsZero() {
		value = start.UTC().Format("2006-01-02 15:04:05.999999")
	}

	pr.wset.set(seenSinceSetting, value)
}
