// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
)

// name of the CEL member function for checking auth freshness. Exposed as `<receiver>.fresh(duration)` in policy expressions.
const authFreshFn = "fresh"

// CerbosAuthCELLib returns the CEL options that make AuthContext and AuthHop
// available to policy expressions and register the `fresh(duration)` member
// function on both types.
//
// The CEL surface this enables in policies:
//
//	P.auth.fresh(duration("5m"))                                 // AuthContext member
//	P.auth.acting_chain.all(h, h.fresh(duration("1h")))          // AuthHop member
//	"mfa" in P.auth.methods                                       // direct field access
//	P.auth.acting_chain.size()                                   // list ops
//
// AuthContext, AuthHop, and the Auth field on Principal/Request_Principal are
// declared in api/public/cerbos/engine/v1/engine.proto. The regenerated pb.go
// gives CEL the field/type reflection metadata it needs. This file only
// registers the user-defined function bindings and the cel.Types() call that
// teaches CEL these are first-class object types (rather than dynamic structs).
//
// The body of `fresh` is currently stubbed to return false unconditionally.
// See the task instruction.md for the full behavioral contract.
func CerbosAuthCELLib() cel.EnvOption {
	return cel.Lib(authLib{})
}

type authLib struct{}

func (authLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Types(&enginev1.AuthContext{}, &enginev1.AuthHop{}),
		cel.Function(authFreshFn,
			cel.MemberOverload(
				"auth_context_fresh_duration",
				[]*cel.Type{cel.ObjectType("cerbos.engine.v1.AuthContext"), cel.DurationType},
				cel.BoolType,
				cel.BinaryBinding(stubAuthFresh),
			),
			cel.MemberOverload(
				"auth_hop_fresh_duration",
				[]*cel.Type{cel.ObjectType("cerbos.engine.v1.AuthHop"), cel.DurationType},
				cel.BoolType,
				cel.BinaryBinding(stubAuthFresh),
			),
		),
	}
}

func (authLib) ProgramOptions() []cel.ProgramOption { return nil }

// stubAuthFresh always returns false. Replace this with the real
// freshness comparison.
func stubAuthFresh(_ ref.Val, _ ref.Val) ref.Val {
	return types.False
}
