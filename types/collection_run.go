// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"errors"
	"strings"
	"time"

	oam "github.com/owasp-amass/open-asset-model"
)

// The states of a collection run.
const (
	RunRunning  = "running"
	RunFinished = "finished"
	RunStopped  = "stopped"
	RunFailed   = "failed"
)

// CollectionRun is one run of a tool that collected data into the Asset
// Database: an Amass enumeration, an import, a scanner, or a person's review.
// Any tool can record its runs, so readers can tell what a run looked for
// and when, and so what a later run no longer found: an asset in a finished
// run's scope whose last-seen time is before that run started was not seen
// by it.
type CollectionRun struct {
	// ID is assigned when the run is started.
	ID string `json:"id"`
	// Tool names what collected, such as "amass", and ToolVersion its
	// version.
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version,omitempty"`
	// ExternalID is the tool's own identifier for the run, such as an Amass
	// session ID.
	ExternalID string    `json:"external_id,omitempty"`
	Status     string    `json:"status"`
	StartedAt  time.Time `json:"started_at"`
	// FinishedAt is zero while the run is running.
	FinishedAt time.Time `json:"finished_at"`
	// Scope is what the run was asked to collect.
	Scope []RunTarget `json:"scope,omitempty"`
	// Metadata holds anything else the tool records about the run, such as
	// its mode.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// RunTarget is one asset in a run's scope, named as the Open Asset Model
// names it: an asset type and the asset's key (FQDN example.com, Netblock
// 192.0.2.0/24, AutonomousSystem 64496).
type RunTarget struct {
	Type oam.AssetType `json:"type"`
	Key  string        `json:"key"`
}

// Validate checks a run before it is started.
func (r *CollectionRun) Validate() error {
	if r == nil {
		return errors.New("the collection run is nil")
	}
	if strings.TrimSpace(r.Tool) == "" {
		return errors.New("a collection run names its tool")
	}
	for _, t := range r.Scope {
		if !validAssetType(t.Type) || strings.TrimSpace(t.Key) == "" {
			return errors.New("a scope target needs an Open Asset Model asset type and a key")
		}
	}

	return nil
}

// FinalRunStatus reports whether status ends a run.
func FinalRunStatus(status string) bool {
	return status == RunFinished || status == RunStopped || status == RunFailed
}

func validAssetType(t oam.AssetType) bool {
	for _, a := range oam.AssetList {
		if a == t {
			return true
		}
	}

	return false
}
