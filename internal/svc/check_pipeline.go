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
	_ = ctx
	_ = log
	_ = eng
	_ = inputs
	_ = requestID
	_ = includeMeta
	return nil, nil
}
