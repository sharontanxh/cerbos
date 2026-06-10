// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"sort"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
)

// planAuditCandidate is an in-flight Plan contribution that may or may not
// survive to the final filter AST. Candidates are added during the per-
// binding loop in planWithAuditTrail; their fate is decided at the elision
// points (const-true DENY nullification, pending-allow nulling, child-
// override short-circuit, no-match action) and at the end of each action.
type planAuditCandidate struct {
	fqn             string
	scope           string
	role            string
	kind            auditv1.PlanContribution_Kind
	isConstTrueDeny bool // true if the DENY's evaluated condition was constant-true
	dead            bool // marked dead by an elision (excluded from final trail)
}

// planAuditTracker accumulates per-action candidate contributions for a
// single planWithAuditTrail invocation. It is NOT safe for concurrent use
// across goroutines, but each Plan call constructs its own tracker so
// callers running in parallel do not share state.
type planAuditTracker struct {
	perAction   map[string][]*planAuditCandidate
	actionOrder []string
}

func newPlanAuditTracker() *planAuditTracker {
	return &planAuditTracker{perAction: make(map[string][]*planAuditCandidate)}
}

func (t *planAuditTracker) seenAction(action string) {
	if _, ok := t.perAction[action]; !ok {
		t.actionOrder = append(t.actionOrder, action)
		t.perAction[action] = nil
	}
}

func (t *planAuditTracker) addAllow(action, fqn, scope, role string) {
	t.seenAction(action)
	t.perAction[action] = append(t.perAction[action], &planAuditCandidate{
		fqn: fqn, scope: scope, role: role,
		kind: auditv1.PlanContribution_KIND_DIRECT_ALLOW,
	})
}

func (t *planAuditTracker) addDeny(action, fqn, scope, role string, fromRolePolicy, isConstTrue bool) {
	t.seenAction(action)
	kind := auditv1.PlanContribution_KIND_INVERTED_DENY_AS_GATE
	if fromRolePolicy {
		kind = auditv1.PlanContribution_KIND_ROLE_POLICY_DENY_AND_GATE
	}
	t.perAction[action] = append(t.perAction[action], &planAuditCandidate{
		fqn: fqn, scope: scope, role: role,
		kind: kind, isConstTrueDeny: isConstTrue,
	})
}

// retagOverrideParentAllow re-tags DIRECT_ALLOW candidates from the given
// (action, scope, role) tuple as OVERRIDE_PARENT_ALLOW_SOURCE. Called when
// a scope with SCOPE_PERMISSIONS_OVERRIDE_PARENT produced an ALLOW (the
// precedence tiebreaker rule).
func (t *planAuditTracker) retagOverrideParentAllow(action, scope, role string) {
	for _, c := range t.perAction[action] {
		if c.dead || c.scope != scope || c.role != role {
			continue
		}
		if c.kind == auditv1.PlanContribution_KIND_DIRECT_ALLOW {
			c.kind = auditv1.PlanContribution_KIND_OVERRIDE_PARENT_ALLOW_SOURCE
		}
	}
}

// nullifyPendingAllow marks all ALLOW candidates for (action, role) as dead.
// Called when a REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS scope produced an ALLOW
// that no parent scope ratified.
func (t *planAuditTracker) nullifyPendingAllow(action, role string) {
	for _, c := range t.perAction[action] {
		if c.dead || c.role != role {
			continue
		}
		if c.kind == auditv1.PlanContribution_KIND_DIRECT_ALLOW ||
			c.kind == auditv1.PlanContribution_KIND_OVERRIDE_PARENT_ALLOW_SOURCE {
			c.dead = true
		}
	}
}

// nullifyConstTrueDeny applies the role-level const-true DENY nullification:
//   - all ALLOW candidates for the role are marked dead
//   - DENY candidates whose individual node was const-true are re-tagged
//     DIRECT_DENY (they determined the role's outcome without surviving
//     structurally in the filter AST)
//   - other DENY candidates for the role are also marked dead (the const-
//     true DENY dominated them)
func (t *planAuditTracker) nullifyConstTrueDeny(action, role string) {
	for _, c := range t.perAction[action] {
		if c.dead || c.role != role {
			continue
		}
		switch c.kind {
		case auditv1.PlanContribution_KIND_DIRECT_ALLOW,
			auditv1.PlanContribution_KIND_OVERRIDE_PARENT_ALLOW_SOURCE:
			c.dead = true
		case auditv1.PlanContribution_KIND_INVERTED_DENY_AS_GATE,
			auditv1.PlanContribution_KIND_ROLE_POLICY_DENY_AND_GATE:
			if c.isConstTrueDeny {
				c.kind = auditv1.PlanContribution_KIND_DIRECT_DENY
			} else {
				c.dead = true
			}
		}
	}
}

// discardAction drops every candidate for the action. Called when no policy
// matched for the action (rootNode is nil after the policyType loop).
func (t *planAuditTracker) discardAction(action string) {
	for _, c := range t.perAction[action] {
		c.dead = true
	}
}

// emit returns the surviving contributions across all actions, sorted by
// (action ASC, policy_fqn ASC, scope ASC, role ASC) per the proto comment.
func (t *planAuditTracker) emit() []*auditv1.PlanContribution {
	var out []*auditv1.PlanContribution
	for _, action := range t.actionOrder {
		for _, c := range t.perAction[action] {
			if c.dead {
				continue
			}
			out = append(out, &auditv1.PlanContribution{
				Action:    action,
				PolicyFqn: c.fqn,
				Scope:     c.scope,
				Role:      c.role,
				Kind:      c.kind,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Action != b.Action {
			return a.Action < b.Action
		}
		if a.PolicyFqn != b.PolicyFqn {
			return a.PolicyFqn < b.PolicyFqn
		}
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		return a.Role < b.Role
	})
	return out
}
