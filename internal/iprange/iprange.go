// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package iprange gives addresses keys that sort as numbers, for the
// repositories that store addresses as text: 16 bytes, an IPv4 address as
// its IPv4-mapped IPv6 form, so one ordering holds both families.
package iprange

import (
	"encoding/hex"
	"errors"
	"net/netip"
)

// MaxLimit is the most results one range read returns.
const MaxLimit = 1000

// Key is the address's 16-byte key.
func Key(a netip.Addr) []byte {
	b := a.Unmap().As16()
	if a.Unmap().Is4() {
		b = netip.AddrFrom4(a.Unmap().As4()).As16()
	}

	return b[:]
}

// Range is the first and last key of the prefix's addresses.
func Range(p netip.Prefix) ([]byte, []byte) {
	p = p.Masked()
	bits := p.Bits()
	if p.Addr().Unmap().Is4() {
		bits += 96
	}

	first := Key(p.Addr())
	last := make([]byte, 16)
	copy(last, first)
	for i := bits; i < 128; i++ {
		last[i/8] |= 0x80 >> (i % 8)
	}

	return first, last
}

// Hex is a key as fixed-width hexadecimal text, which sorts as the key does.
func Hex(key []byte) string {
	return hex.EncodeToString(key)
}

// Check validates a range read's arguments.
func Check(p netip.Prefix, limit int) error {
	if !p.IsValid() {
		return errors.New("a valid CIDR prefix is required")
	}
	if limit < 1 || limit > MaxLimit {
		return errors.New("the limit must be between 1 and 1000")
	}

	return nil
}
