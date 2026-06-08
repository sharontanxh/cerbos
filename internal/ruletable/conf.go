// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package ruletable

// Conf is the runtime configuration for the rule table. Fields and defaults
// are stubbed for the cache-eviction task — the solver fills these in.
type Conf struct{}

// SetDefaults applies default values to unset fields.
func (c *Conf) SetDefaults() {}
