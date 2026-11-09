// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aitestfixture

import (
	"errors"
	"net/url"
	"strings"
)

// validateDisposablePostgresDSN fails closed for ordinary database names.
// DB name convention is only a guardrail: test accounts must be isolated.
func validateDisposablePostgresDSN(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return err
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return errors.New("unexpected PostgreSQL scheme")
	}
	if u.Hostname() == "" || u.User == nil || !strings.HasPrefix(strings.TrimPrefix(u.EscapedPath(),
		"/"), "amass_ai_fixture_") {
		return errors.New("test DSN must name an explicit disposable amass_ai_fixture_* database")
	}

	return nil
}
