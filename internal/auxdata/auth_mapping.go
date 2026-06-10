// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auxdata

import (
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
)

// DeriveAuthContextFromJWTClaims maps the extracted claims of a verified JWT
// into a typed Principal.AuthContext. The standard claim mappings:
//
//   - `auth_time` (numeric, seconds since epoch per OIDC) → AuthContext.AuthTime
//     (google.protobuf.Timestamp)
//
//   - `amr` (string list per OIDC) → AuthContext.Methods
//
//   - `act` (recursive nested object per RFC 8693) → AuthContext.ActingChain,
//     populated in OUTERMOST-first order. The outermost actor is the agent that
//     directly received delegation from the subject; the innermost actor is
//     the leaf caller of the request.
//     Example claim structure:
//         { "sub": "alice",
//           "act": {
//             "sub": "orchestrator", "auth_time": 1717894500,
//             "act": { "sub": "tool-runner", "auth_time": 1717894550 }
//           } }
//     yields acting_chain = [
//         {Id: "orchestrator", AuthTime: 1717894500, ...},
//         {Id: "tool-runner",  AuthTime: 1717894550, ...},
//     ]
//
// Returns nil if `claims` is nil or contains no recognised auth claims (so
// callers can detect "no auth context inferable" cleanly). The auxdata
// pipeline calls this during request extraction and the resulting context is
// surfaced on Principal.AuthContext, with the rule that an EXPLICIT
// caller-supplied Principal.AuthContext takes precedence over the
// auto-derived one.
//
// Currently stubbed to return nil.
func DeriveAuthContextFromJWTClaims(claims map[string]*structpb.Value) *enginev1.AuthContext {
	_ = claims
	return nil
}

// MergeAuthContext combines an explicit caller-supplied AuthContext with one
// auto-derived from JWT claims. Returns the value that should be exposed to
// CEL evaluation as `Principal.AuthContext`. The combine rule is fixed:
//
//   - If `explicit` is non-nil, return it unchanged. The caller has stated
//     intent and that takes precedence over anything inferred from auxData.
//
//   - Otherwise return `derived` (which may itself be nil — for an
//     unauthenticated request neither side carries an AuthContext).
//
// The auxdata pipeline calls this once per request: explicit comes from
// `CheckInput.Principal.Auth` as set by the caller, derived comes from
// `DeriveAuthContextFromJWTClaims` over the verified JWT.
//
// Currently stubbed to return nil.
func MergeAuthContext(explicit, derived *enginev1.AuthContext) *enginev1.AuthContext {
	_ = explicit
	_ = derived
	return nil
}
