// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"context"
	"sync/atomic"

	"go.uber.org/zap"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
)

// Checker is the engine surface this package consumes. Define the methods
// the services depend on.
type Checker interface{}

// Total number of times RunCheckPipeline has been invoked across the process lifetime.
var RunCheckPipelineCallCount atomic.Int64

// RunCheckPipeline runs the shared check-resources flow used by service
// endpoints that go through the engine's Check API.
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
