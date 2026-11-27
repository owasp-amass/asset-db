// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"errors"
	"strings"
	"time"
)

// WorkState is where an item of a work queue is: queued, leased to an
// owner working on it, or done.
type WorkState int

const (
	WorkQueued WorkState = 0
	WorkLeased WorkState = 1
	WorkDone   WorkState = 2
)

// WorkCounts are how many of a queue's items are in each state. An item
// whose lease has expired is counted as queued, since it can be claimed.
type WorkCounts struct {
	Queued int64 `json:"queued"`
	Leased int64 `json:"leased"`
	Done   int64 `json:"done"`
}

// WorkByKind are a queue's counts by kind of work.
type WorkByKind map[string]WorkCounts

// Total is the counts over every kind.
func (m WorkByKind) Total() WorkCounts {
	var t WorkCounts
	for _, c := range m {
		t.Queued += c.Queued
		t.Leased += c.Leased
		t.Done += c.Done
	}
	return t
}

// ErrWorkNotLeased is returned when an owner acks an item it does not
// lease.
var ErrWorkNotLeased = errors.New("the work item is not leased to this owner")

// ValidateWorkClaim checks a claim before it is made.
func ValidateWorkClaim(queue, kind, owner string, n int, ttl time.Duration) error {
	if strings.TrimSpace(queue) == "" || strings.TrimSpace(kind) == "" {
		return errors.New("a claim names its queue and the kind of work")
	}
	if strings.TrimSpace(owner) == "" {
		return errors.New("a claim names its owner")
	}
	if n <= 0 {
		return errors.New("a claim takes at least one item")
	}
	if ttl < 0 {
		return errors.New("a lease cannot last less than no time")
	}
	return nil
}

// WorkKeys checks the keys given for a queue and returns them once each,
// in their first order.
func WorkKeys(queue string, keys []string) ([]string, error) {
	if strings.TrimSpace(queue) == "" {
		return nil, errors.New("work is in a named queue")
	}
	seen := make(map[string]bool, len(keys))
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if k == "" {
			return nil, errors.New("a work item has a key")
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out, nil
}
