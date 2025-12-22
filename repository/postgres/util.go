// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"errors"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// ------------------------------ Utilities ------------------------------------

// parseTimestamp converts a *string timestamp into *time.Time (RFC3339Nano or PostgreSQL
// default format). If parsing fails, returns nil (non-fatal for presentation purposes).
func parseTimestamp(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}

	str := strings.TrimSpace(s)
	if str == "" {
		return time.Time{}, nil
	}

	// Try PostgreSQL's default (YYYY-MM-DD HH:MM:SS.SSS) then RFC3339
	layouts := []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05.000",
		time.RFC3339,
	}

	for _, l := range layouts {
		if t, err := time.Parse(l, str); err == nil {
			return t, nil
		}
	}

	return time.Time{}, errors.New("failed to parse timestamp: " + s)
}
