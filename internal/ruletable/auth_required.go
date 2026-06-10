// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"errors"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
)

// ErrMissingAuthContext is returned by policy evaluation when a policy
// references P.auth.* (directly or transitively through variables or derived
// roles) but the incoming request omits Principal.AuthContext.
//
// The detection happens in two stages:
//
//  1. At policy compile time, an auth-references scanner checks the CEL ASTs of
//     each rule condition, plus any variable definitions and derived-role
//     conditions reached transitively, marking the policy as requiring auth
//     context if any reference path touches P.auth.* / request.principal.auth.*.
//
//  2. At evaluation time, when a marked policy is selected for the request,
//     the evaluator checks whether Principal.AuthContext is populated and
//     returns this sentinel (wrapped via fmt.Errorf("%w: ...", err) so
//     callers can detect it with errors.Is) if not.
//
// Note:
//
//   - Policies that do NOT reference P.auth.* anywhere (directly or
//     transitively) MUST evaluate normally even when Principal.AuthContext
//     is nil — backwards compatibility.
//
//   - Explicit Principal.AuthContext on the request takes precedence over
//     any auxData-derived auth context.
var ErrMissingAuthContext = errors.New("cerbos: policy references P.auth.* but request omits Principal.AuthContext")

// RequireAuthContext is the runtime gate corresponding to the compile-time
// auth-references scanner. Returns ErrMissingAuthContext (wrappable via
// errors.Is) when the policy set is marked as requiring AuthContext and the
// supplied principal lacks Principal.AuthContext. Returns nil otherwise.
//
// Wire this into the evaluator so the gate fires before regular
// rule evaluation and surfaces any missing-context cases distinctly from a
// normal policy deny.
//
// Stubbed to always return nil
func RequireAuthContext(rps *runtimev1.RunnablePolicySet, principal *enginev1.Principal) error {
	_ = compile.PolicyRequiresAuth // companion helper
	_ = rps
	_ = principal
	return nil
}
