// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"context"
	"errors"
	"sync/atomic"

	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
)

// Total number of times RunCheckPipeline has been invoked across the process lifetime
var RunCheckPipelineCallCount atomic.Int64

// RunCheckPipeline runs the shared check-resources flow used by all three
// service endpoints that go through the engine's Check API.
//
// Returns *responsev1.CheckResourcesResponse with RequestId = requestID and
// one ResultEntry per input/output pair, including per-action Meta only when
// includeMeta is true.
//
// Callers first pre-process their service-specific request shapes into the
// shared []*enginev1.CheckInput before invocation. AuxData translation,
// request-limit checks, and AccessEvaluationBatch's principal-grouping all
// stay at the call site.
func RunCheckPipeline(
	ctx context.Context,
	log *zap.Logger,
	eng *engine.Engine,
	inputs []*enginev1.CheckInput,
	requestID string,
	includeMeta bool,
) (*responsev1.CheckResourcesResponse, error) {
	RunCheckPipelineCallCount.Add(1)

	outputs, err := eng.Check(logging.ToContext(ctx, log), inputs)
	if err != nil {
		log.Error("Policy check failed", zap.Error(err))
		if errors.Is(err, compile.PolicyCompilationErr{}) {
			return nil, status.Errorf(codes.FailedPrecondition, "Check failed due to invalid policy")
		}
		return nil, status.Errorf(codes.Internal, "Policy check failed")
	}

	return tracing.RecordSpan2(ctx, "assemble_response", func(_ context.Context, _ trace.Span) (*responsev1.CheckResourcesResponse, error) {
		return buildCheckResourcesResponse(requestID, inputs, outputs, includeMeta), nil
	})
}

// buildCheckResourcesResponse assembles a CheckResourcesResponse from the
// engine outputs. Lifted from the prior inlined implementations in
// CerbosService.CheckResources and AuthzenAuthorizationService (where it
// lived as a package-private helper used by AccessEvaluation +
// AccessEvaluationBatch).
func buildCheckResourcesResponse(requestID string, inputs []*enginev1.CheckInput, outputs []*enginev1.CheckOutput, includeMeta bool) *responsev1.CheckResourcesResponse {
	result := &responsev1.CheckResourcesResponse{
		RequestId: requestID,
		Results:   make([]*responsev1.CheckResourcesResponse_ResultEntry, len(outputs)),
	}

	for i, out := range outputs {
		resource := inputs[i].Resource
		entry := &responsev1.CheckResourcesResponse_ResultEntry{
			Resource: &responsev1.CheckResourcesResponse_ResultEntry_Resource{
				Id:            resource.Id,
				Kind:          resource.Kind,
				PolicyVersion: resource.PolicyVersion,
				Scope:         resource.Scope,
			},
			ValidationErrors: out.ValidationErrors,
			Actions:          make(map[string]effectv1.Effect, len(out.Actions)),
		}

		if includeMeta {
			entry.Meta = &responsev1.CheckResourcesResponse_ResultEntry_Meta{
				EffectiveDerivedRoles: out.EffectiveDerivedRoles,
				Actions:               make(map[string]*responsev1.CheckResourcesResponse_ResultEntry_Meta_EffectMeta, len(out.Actions)),
			}
		}

		if len(out.Outputs) > 0 {
			entry.Outputs = out.Outputs
		}

		for action, actionEffect := range out.Actions {
			entry.Actions[action] = actionEffect.Effect
			if includeMeta {
				entry.Meta.Actions[action] = &responsev1.CheckResourcesResponse_ResultEntry_Meta_EffectMeta{
					MatchedPolicy: actionEffect.Policy,
					MatchedScope:  actionEffect.Scope,
				}
			}
		}

		result.Results[i] = entry
	}

	return result
}
