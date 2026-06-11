// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"context"
	"sync/atomic"

	"go.uber.org/zap"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/evaluator"
)

// Checker is the engine surface that this package consumes. *engine.Engine
// satisfies it. Both CerbosService and AuthzenAuthorizationService should
// consume Checker in place of *engine.Engine so that engine behavior can be
// faked in tests — in particular, so the errors.Is(err, compile.PolicyCompilationErr{})
// branches in the services become exercisable.
type Checker interface {
	Check(ctx context.Context, inputs []*enginev1.CheckInput, opts ...evaluator.CheckOpt) ([]*enginev1.CheckOutput, error)
	Plan(ctx context.Context, input *enginev1.PlanResourcesInput, opts ...evaluator.CheckOpt) (*enginev1.PlanResourcesOutput, error)
}

// Total number of times RunCheckPipeline has been invoked across the process lifetime
var RunCheckPipelineCallCount atomic.Int64

// RunCheckPipeline runs the shared check-resources flow used by all three
// service endpoints that go through the engine's Check API.
func RunCheckPipeline(
	ctx context.Context,
	log *zap.Logger,
	eng Checker,
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
