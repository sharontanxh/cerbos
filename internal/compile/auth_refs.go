// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package compile

import (
	"github.com/google/cel-go/cel"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
)

// ScanAuthReferences reports whether any node path reaches `P.auth.*`
// or `request.principal.auth.*`. This is the single-AST primitive that the
// auth-references scanner is built on.
//
// Intended to cover a single AST.

// Stubbed to always return false in the baseline — no policy requires auth.
func ScanAuthReferences(ast *cel.Ast) bool {
	_ = ast
	return false
}

// PolicyRequiresAuth reports whether a compiled policy set is marked as requiring
// Principal.AuthContext. The marker must be set by the compile pipeline if any
// condition in the policy (transitively, through variables and derived roles)
// references P.auth.*. Read at evaluation time by ruletable.RequireAuthContext.
//
// Stubbed to always return false — no policy is marked in the baseline.
func PolicyRequiresAuth(rps *runtimev1.RunnablePolicySet) bool {
	_ = rps
	return false
}
