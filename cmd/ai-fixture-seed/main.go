// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// ai-fixture-seed is a dangerously writing test utility that refuses normal
// Amass databases. Use only for newly created disposable test databases.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/internal/aitestfixture"
	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fixture seed:", err)
		os.Exit(1)
	}
}

func run() error {
	var dir, sqlite, pgdsn string
	var confirm bool
	flag.StringVar(&dir, "fixture", "testdata/ai", "synthetic JSONL fixture directory")
	flag.StringVar(&sqlite, "sqlite", "", "new disposable SQLite path (must not exist)")
	flag.StringVar(&pgdsn, "postgres-dsn", "", "dedicated disposable PostgreSQL database URL")
	flag.BoolVar(&confirm, "confirm-disposable", false, "required to write a NEW disposable fixture database")
	flag.Parse()
	if !confirm {
		return errors.New("-confirm-disposable required; never seed an existing database")
	}
	if (sqlite == "") == (pgdsn == "") {
		return errors.New("choose exactly one of -sqlite or -postgres-dsn")
	}

	var kind, dsn string
	if sqlite != "" {
		abs, err := filepath.Abs(sqlite)
		if err != nil {
			return err
		}
		if filepath.Ext(abs) != ".db" || strings.Contains(abs, "asset.db") {
			return errors.New("SQLite fixture path must end .db and must not be asset.db")
		}
		if _, err := os.Lstat(abs); err == nil {
			return errors.New("refusing existing SQLite path")
		} else if !os.IsNotExist(err) {
			return err
		}
		if _, err := os.Stat(filepath.Dir(abs)); err != nil {
			return fmt.Errorf("SQLite parent directory must exist: %w", err)
		}

		kind, dsn = sqlite3.SQLite, abs
	} else {
		parsed, err := url.Parse(pgdsn)
		if err != nil {
			return err
		}
		if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
			return errors.New("PostgreSQL DSN must be postgres://")
		}
		if !strings.HasPrefix(strings.TrimPrefix(parsed.Path,
			"/"), "amass_ai_fixture_") || parsed.Host == "" || parsed.User == nil {
			return errors.New("PostgreSQL database name must begin amass_ai_fixture_ and DSN requires explicit host and user")
		}

		kind, dsn = postgres.Postgres, pgdsn
	}

	f, err := aitestfixture.Load(dir)
	if err != nil {
		return err
	}

	db, err := assetdb.New(kind, dsn)
	if err != nil {
		return err
	}

	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	report, err := aitestfixture.Seed(ctx, db, f)
	if err != nil {
		return err
	}

	return json.NewEncoder(os.Stdout).Encode(report)
}
