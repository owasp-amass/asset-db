// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// JournalRecord is one record of the journal: an append-only log that the
// tools sharing a database coordinate through, such as the decisions made
// about its data, the runs and schedules of the tools, and the work they
// share. Records are grouped by topic, and within a topic by kind and by the
// key of what they are about; their data is the tool's own JSON, so a new
// kind of record needs no change to the schema.
type JournalRecord struct {
	// Seq is the record's place in the journal, assigned by the database
	// when it is appended: later records have higher numbers.
	Seq int64 `json:"seq"`
	// Topic groups the records one reader follows, such as "review".
	Topic string `json:"topic"`
	// Kind is the kind of record within its topic.
	Kind string `json:"kind"`
	// Key names what the record is about, such as a proposal ID; it may
	// be empty.
	Key string `json:"key,omitempty"`
	// Data is the record itself, a JSON value; empty is {}.
	Data json.RawMessage `json:"data"`
	// Actor names who wrote it: a tool and host, or a person.
	Actor string `json:"actor,omitempty"`
	// At is when it was appended, set by the database.
	At time.Time `json:"at"`
	// Cause is the Seq of the record that caused this one, or 0.
	Cause int64 `json:"cause,omitempty"`
}

// Validate checks a record before it is appended.
func (r *JournalRecord) Validate() error {
	if r == nil {
		return errors.New("no journal record")
	}
	if strings.TrimSpace(r.Topic) == "" || strings.TrimSpace(r.Kind) == "" {
		return errors.New("a journal record has a topic and a kind")
	}
	if len(r.Data) > 0 && !json.Valid(r.Data) {
		return errors.New("a journal record's data must be JSON")
	}
	if r.Cause < 0 {
		return errors.New("a journal record's cause is a sequence number")
	}
	return nil
}

// JournalData is the record's data, {} when it has none.
func (r *JournalRecord) JournalData() string {
	if len(r.Data) == 0 {
		return "{}"
	}
	return string(r.Data)
}

// Lease is a named piece of work that one holder at a time may do, such as
// reading one version of a document, until it expires or is released.
type Lease struct {
	Name       string          `json:"name"`
	Holder     string          `json:"holder"`
	AcquiredAt time.Time       `json:"acquired_at"`
	ExpiresAt  time.Time       `json:"expires_at"`
	Data       json.RawMessage `json:"data,omitempty"`
}

// ValidateLease checks the arguments of a lease request.
func ValidateLease(name, holder string, ttl time.Duration, data json.RawMessage) error {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(holder) == "" {
		return errors.New("a lease has a name and a holder")
	}
	if ttl <= 0 {
		return errors.New("a lease lasts a positive time")
	}
	if len(data) > 0 && !json.Valid(data) {
		return errors.New("a lease's data must be JSON")
	}
	return nil
}
