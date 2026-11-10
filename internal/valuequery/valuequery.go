// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package valuequery validates the arguments of repository.ValueFinder
// queries for every backend.
package valuequery

import (
	"errors"
	"regexp"
	"strings"

	oam "github.com/owasp-amass/open-asset-model"
)

// MaxLimit bounds a value query.
const MaxLimit = 500

var attributeKey = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Check validates the arguments shared by value queries.
func Check(atype oam.AssetType, name, value string, limit int) error {
	if strings.TrimSpace(string(atype)) == "" {
		return errors.New("asset type required")
	}
	if name == "" || len(name) > 128 {
		return errors.New("property name or attribute key required (at most 128 characters)")
	}
	if value == "" || len(value) > 1024 {
		return errors.New("value required (at most 1024 characters)")
	}
	if limit < 1 || limit > MaxLimit {
		return errors.New("value query limit must be 1..500")
	}

	return nil
}

// CheckKey validates an attribute key, which is written into the
// query so the database can use an expression index on it.
func CheckKey(key string) error {
	if !attributeKey.MatchString(key) {
		return errors.New("attribute key must be a lowercase identifier")
	}

	return nil
}

// LikePattern escapes value for a case-insensitive LIKE contains match with
// ESCAPE '\'.
func LikePattern(value string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(strings.ToLower(value)) + "%"
}
