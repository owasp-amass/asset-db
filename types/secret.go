// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"errors"
	"strings"
	"time"
)

// Secret is a credential the tools sharing a database keep in it, such as a
// data source's API key. The database holds only what the tool encrypted:
// the ciphertext, its nonce and the ID of the key it was encrypted under;
// the tools hold the key.
type Secret struct {
	// Name identifies the secret, such as "Shodan/apikey".
	Name       string    `json:"name"`
	Ciphertext []byte    `json:"ciphertext"`
	Nonce      []byte    `json:"nonce"`
	KeyID      string    `json:"key_id"`
	UpdatedAt  time.Time `json:"updated_at"`
	UpdatedBy  string    `json:"updated_by,omitempty"`
}

// Validate checks a secret before it is stored.
func (s *Secret) Validate() error {
	if s == nil {
		return errors.New("no secret")
	}
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("a secret has a name")
	}
	if len(s.Ciphertext) == 0 || len(s.Nonce) == 0 || strings.TrimSpace(s.KeyID) == "" {
		return errors.New("a secret is stored encrypted: ciphertext, nonce and key ID")
	}
	return nil
}
