// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package valuequery validates the arguments of repository.ValueFinder
// queries for every backend.
package valuequery

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
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

// After parses a page cursor: the entity ID after which a page starts, or
// 0 for the first page.
func After(after string) (int64, error) {
	if after == "" {
		return 0, nil
	}
	id, err := strconv.ParseInt(after, 10, 64)
	if err != nil || id < 1 {
		return 0, errors.New("the page cursor must be an entity ID")
	}

	return id, nil
}

// CheckKey validates an attribute key, which is written into the
// query so the database can use an expression index on it.
func CheckKey(key string) error {
	if !attributeKey.MatchString(key) {
		return errors.New("attribute key must be a lowercase identifier")
	}

	return nil
}

// likeEscaper escapes LIKE's wildcards and its escape character.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// LikePattern escapes value for a case-insensitive LIKE contains match with
// ESCAPE '\'.
func LikePattern(value string) string {
	return "%" + likeEscaper.Replace(strings.ToLower(value)) + "%"
}

// LikePrefix escapes prefix for a case-insensitive LIKE prefix match with
// ESCAPE '\'.
func LikePrefix(prefix string) string {
	return likeEscaper.Replace(strings.ToLower(prefix)) + "%"
}

// MaxHistogramPrefixes bounds the value prefixes one histogram filters by.
const MaxHistogramPrefixes = 64

// CheckHistogram validates the arguments of a value histogram: an asset
// type, a property name or attribute key, and at most MaxHistogramPrefixes
// prefixes of at most 128 characters, none empty.
func CheckHistogram(atype oam.AssetType, name string, prefixes []string) error {
	if strings.TrimSpace(string(atype)) == "" {
		return errors.New("asset type required")
	}
	if name == "" || len(name) > 128 {
		return errors.New("property name or attribute key required (at most 128 characters)")
	}
	if len(prefixes) > MaxHistogramPrefixes {
		return fmt.Errorf("a value histogram filters by at most %d prefixes", MaxHistogramPrefixes)
	}
	for _, p := range prefixes {
		if p == "" || len(p) > 128 {
			return errors.New("a value prefix is 1 to 128 characters")
		}
	}

	return nil
}
