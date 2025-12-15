// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ------------------------------ Utilities ------------------------------------

// parseTimestamp converts a *string timestamp into *time.Time (RFC3339 or SQLite
// default format). If parsing fails, returns nil (non-fatal for presentation purposes).
func parseTimestamp(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}

	str := strings.TrimSpace(s)
	if str == "" {
		return time.Time{}, nil
	}

	// Try SQLite's default (YYYY-MM-DD HH:MM:SS.SSS) then RFC3339
	layouts := []string{
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05.000",
		time.RFC3339,
		time.RFC3339Nano,
	}

	for _, l := range layouts {
		if t, err := time.Parse(l, str); err == nil {
			return t, nil
		}
	}

	return time.Time{}, errors.New("failed to parse timestamp: " + s)
}

func inClause(params []string) (string, []any) {
	if len(params) == 0 {
		return "", nil
	}

	names := make([]string, 0, len(params))
	args := make([]any, 0, len(params))
	for i, p := range params {
		name := fmt.Sprintf("inparam_%d", i)
		names = append(names, ":"+name)
		args = append(args, sql.Named(name, p))
	}

	return "(" + strings.Join(names, ", ") + ")", args
}
