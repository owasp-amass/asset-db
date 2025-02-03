// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"embed"
)

//go:embed *.sql
var postgresMigrations embed.FS

// Migrations returns the migrations for the postgres database.
func Migrations() embed.FS {
	return postgresMigrations
}
