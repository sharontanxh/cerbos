// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"context"
	"sync/atomic"

	"go.uber.org/zap"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/engine"
)

// RunCheckPipelineCallCount is the total number of times RunCheckPipeline
// has been invoked across the process lifetime. Tests use the delta between
// before/after counts to verify that CerbosService.CheckResources,
// AuthzenAuthorizationService.AccessEvaluation, and
// AuthzenAuthorizationService.AccessEvaluationBatch all delegate to the
// shared pipeline rather than retaining their inlined implementations.
var RunCheckPipelineCallCount atomic.Int64

// RunCheckPipeline runs the shared check-resources flow used by all three
// service endpoints that go through the engine's Check API. The contract:
//
//  1. Calls eng.Check(ctx, inputs).
//  2. On error, returns a gRPC status with consistent codes:
//     - compile.PolicyCompilationErr → codes.FailedPrecondition
//     - any other engine error → codes.Internal
//     The log argument is used for the standard "Policy check failed" entry.
//  3. Wraps response assembly in a tracing.RecordSpan2("assemble_response", ...) span,
//     so all three callers gain identical observability (today AccessEvaluationBatch
//     lacks this span — the refactor fixes the asymmetry incidentally).
//  4. Returns *responsev1.CheckResourcesResponse with RequestId = requestID and
//     one ResultEntry per input/output pair, including per-action Meta only when
//     includeMeta is true.
//
// Callers MUST pre-process their service-specific request shapes into the
// shared []*enginev1.CheckInput before invocation. AuxData translation,
// request-limit checks, and AccessEvaluationBatch's principal-grouping all
// stay at the call site.
//
// Stubbed to return (nil, nil) so any unit test asserting on the response
// shape fails on the baseline. The solver implements the body.
func RunCheckPipeline(
	ctx context.Context,
	log *zap.Logger,
	eng *engine.Engine,
	inputs []*enginev1.CheckInput,
	requestID string,
	includeMeta bool,
) (*responsev1.CheckResourcesResponse, error) {
	RunCheckPipelineCallCount.Add(1)
	_ = ctx
	_ = log
	_ = eng
	_ = inputs
	_ = requestID
	_ = includeMeta
	return nil, nil
}
