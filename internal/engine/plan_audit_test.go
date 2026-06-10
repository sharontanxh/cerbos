// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/compile"
	engaudit "github.com/cerbos/cerbos/internal/engine/audit"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
)

// mkInlineEngine writes the given policy YAMLs to a tempdir, builds an
// engine on a disk store backed by that dir, and returns the engine + a
// mock audit log that captures every DecisionLogEntry the engine writes.
//
// Filenames are routed into subdirectories by prefix:
//   - "resource_*"  -> resource_policies/
//   - "principal_*" -> principal_policies/
//   - "role_*"      -> role_policies/
//   - "derived_*"   -> derived_roles/
//   - "schema_*"    -> _schemas/resources/
//   - anything else -> store root
func mkInlineEngine(t *testing.T, policies map[string]string, enforcement schema.Enforcement) (*Engine, *mockAuditLog, context.CancelFunc) {
	t.Helper()
	dir := t.TempDir()

	for name, body := range policies {
		var sub, written string
		switch {
		case strings.HasPrefix(name, "schema_"):
			sub = filepath.Join("_schemas", "resources")
			// Strip the "schema_" prefix so the on-disk filename matches the
			// cerbos:///resources/<name>.json reference used by policies.
			written = strings.TrimPrefix(name, "schema_")
		case strings.HasPrefix(name, "role_"):
			sub = "role_policies"
			written = name
		case strings.HasPrefix(name, "principal_"):
			sub = "principal_policies"
			written = name
		case strings.HasPrefix(name, "resource_"):
			sub = "resource_policies"
			written = name
		case strings.HasPrefix(name, "derived_"):
			sub = "derived_roles"
			written = name
		default:
			sub = ""
			written = name
		}
		full := filepath.Join(dir, sub, written)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(body), 0o644))
	}

	ctx, cancel := context.WithCancel(t.Context())

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(t, err)

	compiler, err := compile.NewManager(ctx, store)
	require.NoError(t, err)

	schemaConf := schema.NewConf(enforcement)
	schemaMgr := schema.NewFromConf(ctx, store, schemaConf)

	rt, err := ruletable.NewRuleTableFromLoader(ctx, compiler)
	require.NoError(t, err)

	mgr, err := ruletable.NewRuleTableManager(rt, compiler, schemaMgr)
	require.NoError(t, err)

	mockLog := &mockAuditLog{}

	evalConf := &evaluator.Conf{}
	evalConf.SetDefaults()

	eng := NewFromConf(ctx, evalConf, Components{
		PolicyLoader:      compiler,
		RuleTableManager:  mgr,
		SchemaMgr:         schemaMgr,
		AuditLog:          mockLog,
		MetadataExtractor: audit.NewMetadataExtractorFromConf(&audit.Conf{}),
	})

	return eng, mockLog, cancel
}

// lastPlanTrail asserts that the mock log captured exactly one Plan entry
// and returns its AuditTrail.
func lastPlanTrail(t *testing.T, m *mockAuditLog) *auditv1.AuditTrail {
	t.Helper()
	logs := m.getDecisionLogs()
	require.Len(t, logs, 1, "expected exactly one decision log entry")
	require.NotNil(t, logs[0].AuditTrail, "decision log entry has no audit trail")
	require.NotNil(t, logs[0].GetPlanResources(), "decision log entry is not a Plan entry")
	return logs[0].AuditTrail
}

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

const fixtureSimpleAllow = `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: doc
  rules:
    - actions: ["view"]
      effect: EFFECT_ALLOW
      roles: ["user"]
      name: simple-allow
`

const fixtureConstFalseDeny = `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: doc
  rules:
    - actions: ["view"]
      effect: EFFECT_ALLOW
      roles: ["user"]
      name: allow-view
    - actions: ["view"]
      effect: EFFECT_DENY
      roles: ["user"]
      name: deny-but-never-fires
      condition:
        match:
          expr: "false"
`

const fixtureConditionalDeny = `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: doc
  rules:
    - actions: ["view"]
      effect: EFFECT_ALLOW
      roles: ["user"]
      name: allow-view
    - actions: ["view"]
      effect: EFFECT_DENY
      roles: ["user"]
      name: conditional-deny
      condition:
        match:
          expr: request.resource.attr.locked == true
`

const fixtureOverrideParentAllow = `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: doc
  scope: "acme"
  scopePermissions: SCOPE_PERMISSIONS_OVERRIDE_PARENT
  rules:
    - actions: ["view"]
      effect: EFFECT_ALLOW
      roles: ["user"]
      name: child-override-allow
`

const fixtureParentResourceConditionalDeny = `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: doc
  rules:
    - actions: ["view"]
      effect: EFFECT_DENY
      roles: ["user"]
      name: parent-conditional-deny
      condition:
        match:
          expr: request.resource.attr.hidden == true
`

const fixtureConstTrueDeny = `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: doc
  rules:
    - actions: ["view"]
      effect: EFFECT_ALLOW
      roles: ["user"]
      name: allow-view
    - actions: ["view"]
      effect: EFFECT_DENY
      roles: ["user"]
      name: const-true-deny
      condition:
        match:
          expr: "true"
`

const fixtureRolePolicyDenyAndGate_RP = `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: doc
  rules:
    - actions: ["view"]
      effect: EFFECT_ALLOW
      roles: ["user"]
      name: resource-allow-view
`

const fixtureRolePolicyDenyAndGate_Role = `apiVersion: api.cerbos.dev/v1
rolePolicy:
  role: user
  rules:
    - resource: doc
      allowActions: ["view"]
      condition:
        match:
          expr: request.resource.attr.region == "us"
`

const fixtureSchemaRejectionResource = `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: doc
  schemas:
    resourceSchema:
      ref: cerbos:///resources/doc.json
  rules:
    - actions: ["view"]
      effect: EFFECT_ALLOW
      roles: ["user"]
      name: allow-view
`

const fixtureSchemaRejectionSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "region": {
      "type": "string",
      "enum": ["us", "eu"]
    }
  },
  "required": ["region"]
}`

const fixturePendingAllowChild = `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: doc
  scope: "acme"
  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
  rules:
    - actions: ["view"]
      effect: EFFECT_ALLOW
      roles: ["user"]
      name: child-allow-view-needs-consent
`

const fixturePendingAllowParentEditOnly = `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: doc
  rules:
    - actions: ["edit"]
      effect: EFFECT_ALLOW
      roles: ["user"]
      name: parent-allow-edit
`

const fixtureDerivedRoleDef = `apiVersion: api.cerbos.dev/v1
derivedRoles:
  name: user_owners
  definitions:
    - name: owner
      parentRoles: ["user"]
      condition:
        match:
          expr: request.resource.attr.owner == request.principal.id
`

const fixtureDerivedRoleResource = `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: doc
  importDerivedRoles:
    - user_owners
  rules:
    - actions: ["edit"]
      effect: EFFECT_ALLOW
      derivedRoles: ["owner"]
      name: edit-as-owner
      condition:
        match:
          expr: request.resource.attr.status == "draft"
`

const fixtureWildcardAllow = `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: doc
  rules:
    - actions: ["*"]
      effect: EFFECT_ALLOW
      roles: ["user"]
      name: wildcard-allow
`

const fixtureConstFalseAllow = `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: doc
  rules:
    - actions: ["view"]
      effect: EFFECT_ALLOW
      roles: ["user"]
      name: allow-view-conditional
      condition:
        match:
          expr: request.resource.attr.public == true
    - actions: ["view"]
      effect: EFFECT_ALLOW
      roles: ["user"]
      name: allow-view-const-false
      condition:
        match:
          expr: "false"
`

const fixturePerActionSameRuleDifferentFate = `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: doc
  rules:
    - actions: ["view", "edit"]
      effect: EFFECT_ALLOW
      roles: ["user"]
      name: allow-view-and-edit
    - actions: ["edit"]
      effect: EFFECT_DENY
      roles: ["user"]
      name: unconditional-deny-edit
`

// ---------------------------------------------------------------------------
// F2P tests. Each fails on the stubs branch (PlanContributions is always
// empty) and is intended to pass once the solver wires up plan.go.
// ---------------------------------------------------------------------------

func TestPlanAudit_DirectAllow_BasicSurvival(t *testing.T) {
	eng, mockLog, cancel := mkInlineEngine(t, map[string]string{
		"resource_doc.yaml": fixtureSimpleAllow,
	}, schema.EnforcementNone)
	defer cancel()

	req := &enginev1.PlanResourcesInput{
		RequestId: "t-direct-allow",
		Principal: &enginev1.Principal{Id: "alice", Roles: []string{"user"}},
		Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "doc"},
		Actions:   []string{"view"},
	}
	_, err := eng.Plan(t.Context(), req)
	require.NoError(t, err)

	trail := lastPlanTrail(t, mockLog)
	require.Len(t, trail.PlanContributions, 1, "expected exactly one contribution; got %+v", trail.PlanContributions)
	c := trail.PlanContributions[0]
	require.Equal(t, "view", c.Action)
	require.Equal(t, auditv1.PlanContribution_KIND_DIRECT_ALLOW, c.Kind)
	require.Contains(t, c.PolicyFqn, "doc")
	require.Equal(t, "user", c.Role)
}

func TestPlanAudit_ConstFalseDeny_ExcludedFromContributions(t *testing.T) {
	// Discriminator: distinguishes "binding matched and was evaluated" from
	// "binding produced a node that survived into the filter". A cheap
	// solution that records every matched binding leaks the const-false
	// DENY here.
	eng, mockLog, cancel := mkInlineEngine(t, map[string]string{
		"resource_doc.yaml": fixtureConstFalseDeny,
	}, schema.EnforcementNone)
	defer cancel()

	req := &enginev1.PlanResourcesInput{
		RequestId: "t-cf-deny",
		Principal: &enginev1.Principal{Id: "alice", Roles: []string{"user"}},
		Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "doc"},
		Actions:   []string{"view"},
	}
	_, err := eng.Plan(t.Context(), req)
	require.NoError(t, err)

	trail := lastPlanTrail(t, mockLog)
	require.NotEmpty(t, trail.PlanContributions, "allow contribution should still be present")
	for _, c := range trail.PlanContributions {
		// No DENY-flavoured kind should appear: the only DENY in the
		// fixture is const-false and must be elided.
		require.NotEqual(t, auditv1.PlanContribution_KIND_DIRECT_DENY, c.Kind,
			"const-false DENY leaked as DIRECT_DENY: %+v", c)
		require.NotEqual(t, auditv1.PlanContribution_KIND_INVERTED_DENY_AS_GATE, c.Kind,
			"const-false DENY leaked as INVERTED_DENY_AS_GATE: %+v", c)
	}
}

func TestPlanAudit_InvertedDenyAsGate(t *testing.T) {
	// A non-role-policy DENY with a non-constant condition survives the
	// scope/role/policyType aggregation and is inverted at the policyType
	// level (plan.go:347-354). It MUST be tagged INVERTED_DENY_AS_GATE.
	eng, mockLog, cancel := mkInlineEngine(t, map[string]string{
		"resource_doc.yaml": fixtureConditionalDeny,
	}, schema.EnforcementNone)
	defer cancel()

	req := &enginev1.PlanResourcesInput{
		RequestId: "t-inv-deny",
		Principal: &enginev1.Principal{Id: "alice", Roles: []string{"user"}},
		Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "doc"},
		Actions:   []string{"view"},
	}
	_, err := eng.Plan(t.Context(), req)
	require.NoError(t, err)

	trail := lastPlanTrail(t, mockLog)
	var hasInverted, hasAllow bool
	for _, c := range trail.PlanContributions {
		if c.Kind == auditv1.PlanContribution_KIND_INVERTED_DENY_AS_GATE {
			hasInverted = true
		}
		if c.Kind == auditv1.PlanContribution_KIND_DIRECT_ALLOW {
			hasAllow = true
		}
	}
	require.True(t, hasAllow, "expected DIRECT_ALLOW contribution; got: %+v", trail.PlanContributions)
	require.True(t, hasInverted, "expected INVERTED_DENY_AS_GATE contribution; got: %+v", trail.PlanContributions)
}

func TestPlanAudit_OverrideParentAllowSource_PrecedenceOverDirectAllow(t *testing.T) {
	// A child OVERRIDE_PARENT scope's unconditional ALLOW both (a) survives
	// as a contribution, and (b) suppresses parent-scope walks. By
	// precedence, that binding MUST be tagged
	// OVERRIDE_PARENT_ALLOW_SOURCE (Kind value 6 > DIRECT_ALLOW = 1).
	eng, mockLog, cancel := mkInlineEngine(t, map[string]string{
		"resource_doc_parent.yaml": fixtureParentResourceConditionalDeny,
		"resource_doc_child.yaml":  fixtureOverrideParentAllow,
	}, schema.EnforcementNone)
	defer cancel()

	req := &enginev1.PlanResourcesInput{
		RequestId: "t-override",
		Principal: &enginev1.Principal{Id: "alice", Roles: []string{"user"}},
		Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "doc", Scope: "acme"},
		Actions:   []string{"view"},
	}
	_, err := eng.Plan(t.Context(), req)
	require.NoError(t, err)

	trail := lastPlanTrail(t, mockLog)
	var overrideFound bool
	for _, c := range trail.PlanContributions {
		if c.Kind == auditv1.PlanContribution_KIND_OVERRIDE_PARENT_ALLOW_SOURCE {
			overrideFound = true
			require.Equal(t, "acme", c.Scope, "OVERRIDE_PARENT_ALLOW_SOURCE should carry the child scope")
		}
		// Child-scope ALLOW must NOT be tagged DIRECT_ALLOW — precedence wins.
		if c.Scope == "acme" {
			require.NotEqual(t, auditv1.PlanContribution_KIND_DIRECT_ALLOW, c.Kind,
				"child-scope ALLOW with OVERRIDE_PARENT must use OVERRIDE_PARENT_ALLOW_SOURCE, not DIRECT_ALLOW")
		}
	}
	require.True(t, overrideFound,
		"expected OVERRIDE_PARENT_ALLOW_SOURCE contribution from acme scope; got: %+v",
		trail.PlanContributions)
}

func TestPlanAudit_OverrideParent_SuppressedParentScopeBindingsExcluded(t *testing.T) {
	// Same fixture as the precedence test. Because the child OVERRIDE_PARENT
	// produces an unconditional ALLOW, the parent-scope conditional DENY
	// must NOT appear (plan.go:137-139 short-circuit).
	eng, mockLog, cancel := mkInlineEngine(t, map[string]string{
		"resource_doc_parent.yaml": fixtureParentResourceConditionalDeny,
		"resource_doc_child.yaml":  fixtureOverrideParentAllow,
	}, schema.EnforcementNone)
	defer cancel()

	req := &enginev1.PlanResourcesInput{
		RequestId: "t-override-suppress",
		Principal: &enginev1.Principal{Id: "alice", Roles: []string{"user"}},
		Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "doc", Scope: "acme"},
		Actions:   []string{"view"},
	}
	_, err := eng.Plan(t.Context(), req)
	require.NoError(t, err)

	trail := lastPlanTrail(t, mockLog)
	require.NotEmpty(t, trail.PlanContributions,
		"expected at least one contribution from the child OVERRIDE_PARENT scope")
	for _, c := range trail.PlanContributions {
		require.NotEqual(t, "", c.Scope,
			"parent-scope binding leaked into trail after child override short-circuit: %+v", c)
		require.NotEqual(t, auditv1.PlanContribution_KIND_INVERTED_DENY_AS_GATE, c.Kind,
			"parent-scope conditional DENY should not appear")
	}
}

func TestPlanAudit_BackwardCompat_EffectivePoliciesUnchanged(t *testing.T) {
	// EffectivePolicies must remain populated regardless of the new field.
	// Catches solutions that accidentally short-circuit EffectivePolicies
	// while wiring up PlanContributions.
	eng, mockLog, cancel := mkInlineEngine(t, map[string]string{
		"resource_doc.yaml": fixtureSimpleAllow,
	}, schema.EnforcementNone)
	defer cancel()

	req := &enginev1.PlanResourcesInput{
		RequestId: "t-backcompat",
		Principal: &enginev1.Principal{Id: "alice", Roles: []string{"user"}},
		Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "doc"},
		Actions:   []string{"view"},
	}
	_, err := eng.Plan(t.Context(), req)
	require.NoError(t, err)

	trail := lastPlanTrail(t, mockLog)
	require.NotEmpty(t, trail.EffectivePolicies,
		"EffectivePolicies must remain populated regardless of PlanContributions")
}

func TestPlanAudit_MergeTrails_EffectivePoliciesBehaviorPreserved(t *testing.T) {
	// MergeTrails only knows about EffectivePolicies. Passing trails with
	// PlanContributions through it MUST leave EffectivePolicies behaviour
	// identical to the pre-change implementation. The new field's merge
	// semantics are deliberately out-of-scope for this task — this test
	// only locks the EP behaviour.
	a := &auditv1.AuditTrail{
		EffectivePolicies: map[string]*policyv1.SourceAttributes{
			"ep-a": {Attributes: map[string]*structpb.Value{}},
		},
		PlanContributions: []*auditv1.PlanContribution{
			{Action: "view", PolicyFqn: "p1", Kind: auditv1.PlanContribution_KIND_DIRECT_ALLOW},
		},
	}
	b := &auditv1.AuditTrail{
		EffectivePolicies: map[string]*policyv1.SourceAttributes{
			"ep-b": {Attributes: map[string]*structpb.Value{}},
		},
		PlanContributions: []*auditv1.PlanContribution{
			{Action: "edit", PolicyFqn: "p2", Kind: auditv1.PlanContribution_KIND_DIRECT_DENY},
		},
	}
	merged := engaudit.MergeTrails(a, b)
	require.NotNil(t, merged)
	require.Contains(t, merged.EffectivePolicies, "ep-a")
	require.Contains(t, merged.EffectivePolicies, "ep-b")
}

func TestPlanAudit_Ordering_SortedByActionFqnScopeRole(t *testing.T) {
	// PlanContributions must be deterministically ordered by
	// (action ASC, policy_fqn ASC, scope ASC, role ASC) — tests rely on
	// this for direct slice equality.
	eng, mockLog, cancel := mkInlineEngine(t, map[string]string{
		"resource_doc.yaml": fixtureConditionalDeny,
	}, schema.EnforcementNone)
	defer cancel()

	req := &enginev1.PlanResourcesInput{
		RequestId: "t-ordering",
		Principal: &enginev1.Principal{Id: "alice", Roles: []string{"user"}},
		Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "doc"},
		Actions:   []string{"view"},
	}
	_, err := eng.Plan(t.Context(), req)
	require.NoError(t, err)

	trail := lastPlanTrail(t, mockLog)
	require.NotEmpty(t, trail.PlanContributions)
	sorted := slices.Clone(trail.PlanContributions)
	sort.SliceStable(sorted, func(i, j int) bool {
		ci, cj := sorted[i], sorted[j]
		if ci.Action != cj.Action {
			return ci.Action < cj.Action
		}
		if ci.PolicyFqn != cj.PolicyFqn {
			return ci.PolicyFqn < cj.PolicyFqn
		}
		if ci.Scope != cj.Scope {
			return ci.Scope < cj.Scope
		}
		return ci.Role < cj.Role
	})
	require.Equal(t, sorted, trail.PlanContributions,
		"PlanContributions must be pre-sorted by (action, policy_fqn, scope, role)")
}

func TestPlanAudit_ConcurrentCalls_RaceFree(t *testing.T) {
	// Multiple concurrent Plan calls against the same engine must produce
	// per-call trails with no data races. A cheap solution that mutates a
	// shared trail map on the engine or rule-table struct will fail under
	// `go test -race`. Each per-call trail must additionally carry the
	// expected contribution (proving per-call isolation, not just race
	// freedom).
	eng, mockLog, cancel := mkInlineEngine(t, map[string]string{
		"resource_doc.yaml": fixtureSimpleAllow,
	}, schema.EnforcementNone)
	defer cancel()

	const goroutines = 16
	const calls = 4

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*calls)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < calls; j++ {
				req := &enginev1.PlanResourcesInput{
					RequestId: fmt.Sprintf("t-race-%d-%d", i, j),
					Principal: &enginev1.Principal{Id: "alice", Roles: []string{"user"}},
					Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "doc"},
					Actions:   []string{"view"},
				}
				if _, err := eng.Plan(t.Context(), req); err != nil {
					errCh <- err
				}
			}
		}(i)
	}
	wg.Wait()
	close(errCh)

	var errs []error
	for e := range errCh {
		errs = append(errs, e)
	}
	require.NoError(t, errors.Join(errs...))

	logs := mockLog.getDecisionLogs()
	require.Equal(t, goroutines*calls, len(logs), "every call must produce its own decision log")
	for _, e := range logs {
		require.NotNil(t, e.AuditTrail)
		require.Len(t, e.AuditTrail.PlanContributions, 1,
			"each per-call trail must carry exactly one contribution for this fixture")
		require.Equal(t, auditv1.PlanContribution_KIND_DIRECT_ALLOW,
			e.AuditTrail.PlanContributions[0].Kind)
	}
}

func TestPlanAudit_ConstTrueDeny_TaggedDirectDeny_NullifiedAllowExcluded(t *testing.T) {
	// A DENY binding whose condition evaluates to constant-true nullifies the
	// role's ALLOW (plan.go:295-309). Per the spec's DIRECT_DENY redefinition,
	// the nullifying DENY MUST be tagged DIRECT_DENY (it determined the
	// outcome without surviving structurally in the AST), and the nullified
	// ALLOW MUST be excluded.
	eng, mockLog, cancel := mkInlineEngine(t, map[string]string{
		"resource_doc.yaml": fixtureConstTrueDeny,
	}, schema.EnforcementNone)
	defer cancel()

	req := &enginev1.PlanResourcesInput{
		RequestId: "t-const-true-deny",
		Principal: &enginev1.Principal{Id: "alice", Roles: []string{"user"}},
		Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "doc"},
		Actions:   []string{"view"},
	}
	_, err := eng.Plan(t.Context(), req)
	require.NoError(t, err)

	trail := lastPlanTrail(t, mockLog)
	var hasDirectDeny, hasDirectAllow bool
	for _, c := range trail.PlanContributions {
		if c.Kind == auditv1.PlanContribution_KIND_DIRECT_DENY {
			hasDirectDeny = true
		}
		if c.Kind == auditv1.PlanContribution_KIND_DIRECT_ALLOW {
			hasDirectAllow = true
		}
	}
	require.True(t, hasDirectDeny,
		"expected DIRECT_DENY for the const-true DENY that nullified the role allow; got: %+v",
		trail.PlanContributions)
	require.False(t, hasDirectAllow,
		"the nullified ALLOW MUST NOT appear; got: %+v",
		trail.PlanContributions)
}

func TestPlanAudit_RolePolicyDenyAndGate(t *testing.T) {
	// A role policy with allowActions + a condition synthesizes a DENY
	// binding marked FromRolePolicy=true (index.go:486-498). That DENY
	// is AND-gated onto the role's allow at plan.go:321-326. The
	// contribution MUST be tagged ROLE_POLICY_DENY_AND_GATE, distinct
	// from a top-level INVERTED_DENY_AS_GATE.
	eng, mockLog, cancel := mkInlineEngine(t, map[string]string{
		"resource_doc.yaml":  fixtureRolePolicyDenyAndGate_RP,
		"role_user_doc.yaml": fixtureRolePolicyDenyAndGate_Role,
	}, schema.EnforcementNone)
	defer cancel()

	req := &enginev1.PlanResourcesInput{
		RequestId: "t-role-policy-and-gate",
		Principal: &enginev1.Principal{Id: "alice", Roles: []string{"user"}},
		Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "doc"},
		Actions:   []string{"view"},
	}
	_, err := eng.Plan(t.Context(), req)
	require.NoError(t, err)

	trail := lastPlanTrail(t, mockLog)
	var hasRolePolicyGate, hasDirectAllow bool
	for _, c := range trail.PlanContributions {
		if c.Kind == auditv1.PlanContribution_KIND_ROLE_POLICY_DENY_AND_GATE {
			hasRolePolicyGate = true
		}
		if c.Kind == auditv1.PlanContribution_KIND_DIRECT_ALLOW {
			hasDirectAllow = true
		}
	}
	require.True(t, hasDirectAllow,
		"expected DIRECT_ALLOW from resource policy; got: %+v", trail.PlanContributions)
	require.True(t, hasRolePolicyGate,
		"expected ROLE_POLICY_DENY_AND_GATE from role-policy synthesized DENY; got: %+v",
		trail.PlanContributions)
}

func TestPlanAudit_SchemaRejection(t *testing.T) {
	// When the request resource fails schema validation and enforcement is
	// set to reject (plan.go:81-86), Plan short-circuits with an
	// ALWAYS_DENIED filter and no bindings are walked. The trail MUST
	// contain exactly one contribution tagged SCHEMA_REJECTION, with
	// action/scope/role empty (no per-action evaluation happened).
	eng, mockLog, cancel := mkInlineEngine(t, map[string]string{
		"resource_doc.yaml": fixtureSchemaRejectionResource,
		"schema_doc.json":   fixtureSchemaRejectionSchema,
	}, schema.EnforcementReject)
	defer cancel()

	req := &enginev1.PlanResourcesInput{
		RequestId: "t-schema-reject",
		Principal: &enginev1.Principal{Id: "alice", Roles: []string{"user"}},
		Resource: &enginev1.PlanResourcesInput_Resource{
			Kind: "doc",
			Attr: map[string]*structpb.Value{
				"region": structpb.NewStringValue("asia"), // not in {us, eu}
			},
		},
		Actions: []string{"view"},
	}
	_, err := eng.Plan(t.Context(), req)
	require.NoError(t, err) // schema rejection produces ALWAYS_DENIED, not a Go error

	trail := lastPlanTrail(t, mockLog)
	require.Len(t, trail.PlanContributions, 1,
		"schema rejection must produce exactly one SCHEMA_REJECTION contribution; got: %+v",
		trail.PlanContributions)
	c := trail.PlanContributions[0]
	require.Equal(t, auditv1.PlanContribution_KIND_SCHEMA_REJECTION, c.Kind)
	require.Empty(t, c.Action, "SCHEMA_REJECTION contribution must have empty action")
	require.Empty(t, c.Scope, "SCHEMA_REJECTION contribution must have empty scope")
	require.Empty(t, c.Role, "SCHEMA_REJECTION contribution must have empty role")
}

func TestPlanAudit_PendingAllowNulled_ExcludedButOtherActionsSurvive(t *testing.T) {
	// A REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS scope's ALLOW is nulled if no
	// parent scope ratifies (plan.go:290-292). That binding MUST be excluded
	// from PlanContributions for the affected action. Other actions that
	// don't hit the pending-allow path MUST still produce contributions.
	eng, mockLog, cancel := mkInlineEngine(t, map[string]string{
		"resource_doc_child.yaml":  fixturePendingAllowChild,
		"resource_doc_parent.yaml": fixturePendingAllowParentEditOnly,
	}, schema.EnforcementNone)
	defer cancel()

	req := &enginev1.PlanResourcesInput{
		RequestId: "t-pending-allow",
		Principal: &enginev1.Principal{Id: "alice", Roles: []string{"user"}},
		Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "doc", Scope: "acme"},
		Actions:   []string{"view", "edit"},
	}
	_, err := eng.Plan(t.Context(), req)
	require.NoError(t, err)

	trail := lastPlanTrail(t, mockLog)
	var viewCount, editCount int
	for _, c := range trail.PlanContributions {
		if c.Action == "view" {
			viewCount++
		}
		if c.Action == "edit" {
			editCount++
		}
	}
	require.Greater(t, editCount, 0,
		"edit action must have at least one contribution (parent-scope allow); got trail: %+v",
		trail.PlanContributions)
	require.Equal(t, 0, viewCount,
		"view's pending-allow was nulled; MUST NOT appear in contributions; got trail: %+v",
		trail.PlanContributions)
}

func TestPlanAudit_DerivedRolePlusCoreCondition_SingleContribution(t *testing.T) {
	// A binding with BOTH a derived-role condition and a core condition
	// (plan.go:215-235 combines them into a single QpN) MUST produce
	// exactly one contribution — not two. Catches solutions that emit
	// a contribution per condition node.
	eng, mockLog, cancel := mkInlineEngine(t, map[string]string{
		"derived_user_owners.yaml": fixtureDerivedRoleDef,
		"resource_doc.yaml":        fixtureDerivedRoleResource,
	}, schema.EnforcementNone)
	defer cancel()

	req := &enginev1.PlanResourcesInput{
		RequestId: "t-derived-role-single",
		Principal: &enginev1.Principal{Id: "alice", Roles: []string{"user"}},
		Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "doc"},
		Actions:   []string{"edit"},
	}
	_, err := eng.Plan(t.Context(), req)
	require.NoError(t, err)

	trail := lastPlanTrail(t, mockLog)
	require.Len(t, trail.PlanContributions, 1,
		"a binding combining a derived role condition and a core condition MUST produce ONE contribution, not two; got: %+v",
		trail.PlanContributions)
	c := trail.PlanContributions[0]
	require.Equal(t, "edit", c.Action)
	require.Equal(t, auditv1.PlanContribution_KIND_DIRECT_ALLOW, c.Kind)
}

func TestPlanAudit_PerAction_WildcardBindingContributesOncePerAction(t *testing.T) {
	// A wildcard binding (`actions: ["*"]`) fires for every requested
	// action. PlanContributions MUST record one contribution per concrete
	// requested action — not one with the wildcard and not deduplicated
	// across actions. This locks the "per-action concrete recording"
	// requirement from instruction.md.
	eng, mockLog, cancel := mkInlineEngine(t, map[string]string{
		"resource_doc.yaml": fixtureWildcardAllow,
	}, schema.EnforcementNone)
	defer cancel()

	req := &enginev1.PlanResourcesInput{
		RequestId: "t-per-action-wildcard",
		Principal: &enginev1.Principal{Id: "alice", Roles: []string{"user"}},
		Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "doc"},
		Actions:   []string{"view", "edit"},
	}
	_, err := eng.Plan(t.Context(), req)
	require.NoError(t, err)

	trail := lastPlanTrail(t, mockLog)
	require.Len(t, trail.PlanContributions, 2,
		"wildcard binding requested for 2 actions must produce 2 contributions (one per concrete action); got: %+v",
		trail.PlanContributions)
	seen := map[string]bool{}
	for _, c := range trail.PlanContributions {
		require.Equal(t, auditv1.PlanContribution_KIND_DIRECT_ALLOW, c.Kind)
		require.NotEqual(t, "*", c.Action,
			"contribution must record the concrete requested action, not the binding wildcard")
		seen[c.Action] = true
	}
	require.True(t, seen["view"], "missing contribution for action=view")
	require.True(t, seen["edit"], "missing contribution for action=edit")
}

func TestPlanAudit_ConstFalseAllow_ExcludedFromContributions(t *testing.T) {
	// The EXCLUDE rule "Bindings whose evaluated condition is constant-false"
	// is symmetric across effects — it applies to ALLOW bindings too, not
	// only DENYs (where plan.go has an explicit short-circuit at line 242).
	// Catches solutions that only special-case the DENY path.
	//
	// Fixture: two ALLOW bindings for the same role on "view". One is
	// conditional (survives). One is const-false (must be excluded). Only
	// one contribution should be recorded.
	eng, mockLog, cancel := mkInlineEngine(t, map[string]string{
		"resource_doc.yaml": fixtureConstFalseAllow,
	}, schema.EnforcementNone)
	defer cancel()

	req := &enginev1.PlanResourcesInput{
		RequestId: "t-cf-allow",
		Principal: &enginev1.Principal{Id: "alice", Roles: []string{"user"}},
		Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "doc"},
		Actions:   []string{"view"},
	}
	_, err := eng.Plan(t.Context(), req)
	require.NoError(t, err)

	trail := lastPlanTrail(t, mockLog)
	require.Len(t, trail.PlanContributions, 1,
		"const-false ALLOW must be excluded; only the conditional ALLOW should contribute. got: %+v",
		trail.PlanContributions)
	c := trail.PlanContributions[0]
	require.Equal(t, auditv1.PlanContribution_KIND_DIRECT_ALLOW, c.Kind)
}

func TestPlanAudit_PerAction_SameRuleDifferentFatePerAction(t *testing.T) {
	// Strongest reading of "same rules could contribute differently to
	// different actions": one ALLOW binding fires for BOTH "view" and "edit",
	// but for "edit" there's also an unconditional DENY that nullifies the
	// role's ALLOW.
	//
	// Per-action fate of the SAME "allow-view-and-edit" binding:
	//   view : survives          -> DIRECT_ALLOW contribution
	//   edit : nullified by DENY -> EXCLUDED
	//
	// And the unconditional DENY:
	//   edit : nullifier         -> DIRECT_DENY contribution
	//
	// A cheap solution that records contributions per-binding-match without
	// per-action survival reconciliation will report the allow-and-edit
	// binding under both actions, failing this test.
	eng, mockLog, cancel := mkInlineEngine(t, map[string]string{
		"resource_doc.yaml": fixturePerActionSameRuleDifferentFate,
	}, schema.EnforcementNone)
	defer cancel()

	req := &enginev1.PlanResourcesInput{
		RequestId: "t-per-action-same-rule",
		Principal: &enginev1.Principal{Id: "alice", Roles: []string{"user"}},
		Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "doc"},
		Actions:   []string{"view", "edit"},
	}
	_, err := eng.Plan(t.Context(), req)
	require.NoError(t, err)

	trail := lastPlanTrail(t, mockLog)

	var viewContribs, editContribs []*auditv1.PlanContribution
	for _, c := range trail.PlanContributions {
		switch c.Action {
		case "view":
			viewContribs = append(viewContribs, c)
		case "edit":
			editContribs = append(editContribs, c)
		}
	}

	require.Len(t, viewContribs, 1,
		"view: same rule survives as DIRECT_ALLOW; expected one contribution. got: %+v",
		viewContribs)
	require.Equal(t, auditv1.PlanContribution_KIND_DIRECT_ALLOW, viewContribs[0].Kind)

	require.Len(t, editContribs, 1,
		"edit: nullifier should produce one DIRECT_DENY; the nullified ALLOW MUST NOT appear. got: %+v",
		editContribs)
	require.Equal(t, auditv1.PlanContribution_KIND_DIRECT_DENY, editContribs[0].Kind)
}
