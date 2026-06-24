// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package inspect

import (
	"errors"

	"github.com/cerbos/cerbos/internal/policy"
)

// ErrPolicyKindMismatch is returned by Diff when the two policies are of different kinds
// (e.g. one ResourcePolicy and one PrincipalPolicy).
var ErrPolicyKindMismatch = errors.New("policy kind mismatch")

// EntityDiff records the names added, removed, and changed for a single entity type
// (actions, attributes, constants, variables, derived roles) between two policy revisions.
// Each slice contains identifying names: the action verb, the constant/variable name,
// the imported derived role name, or the attribute path (e.g. "R.attr.department").
type EntityDiff struct {
	Added   []string
	Removed []string
	Changed []string
}

// PolicyDiff is the structured difference between two revisions of the same policy.
// Fields that do not apply to the policy's kind (e.g. DerivedRoles for a PrincipalPolicy)
// MUST be the zero value EntityDiff{}.
type PolicyDiff struct {
	Actions      EntityDiff
	Attributes   EntityDiff
	Constants    EntityDiff
	Variables    EntityDiff
	DerivedRoles EntityDiff
}

// Diff computes the structured difference between two revisions of the same policy.
// The two policies MUST be of the same kind; otherwise ErrPolicyKindMismatch is returned.
//
// Diff MUST operate on policy AST and string forms only; it MUST NOT compile or
// evaluate any expressions (CEL or otherwise). Variable bodies in particular
// reference identifiers (e.g. P.role) that have no resolvable binding at this
// layer, so any compilation pass will error on otherwise-valid policies.
//
// "Changed" populates only for entities that have a value to compare:
//   - constants: literal value changed
//   - variables: expression changed
//
// For actions, attributes, and derived role imports (which are bare identifiers with
// no value to compare), Changed is always empty.
//
// Scope of attribute extraction: attribute references of the form "R.attr.NAME" are
// extracted from rule-condition expressions only. Variable bodies and constant values
// are NOT scanned for attribute references — Variables.Changed and Constants.Changed
// already capture those at their own level, and propagating their internals here would
// double-count when a variable's body merely shifts.
func Diff(a, b *policy.Wrapper) (*PolicyDiff, error) {
	return nil, errors.New("not implemented")
}
