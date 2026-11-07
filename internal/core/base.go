package core

import (
	"context"
	"sync"
	"time"

	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/projection"
	"github.com/brickKit/be-sdk-go/v3/runtime"
)

// Base is what every module works with: the component's runtime; the deployment and this member's instance; the
// registry (AUTHZ_REGISTRY, parsed again only when it changes: RegistryNow); the identity member's account status with
// its watermark and the source's bounds (D_src_high, D_src_read, T_tight, security 03); the unit depth (A131); the
// plans' bounds (A132); and the hook the effect point calls when it moves a record's state.
type Base struct {
	RT                   *runtime.Runtime
	Deployment, Instance string
	RegistryText         func() string

	mu      sync.Mutex
	regText string
	reg     Registry

	Accounts                *projection.Watermarked
	SrcHigh, SrcRead, Tight time.Duration
	MaxDepth                int           // AUTHZ_MAX_UNIT_DEPTH (A131)
	PlanMaxAge              time.Duration // AUTHZ_PLAN_MAX_AGE (A132)
	PlanConfirmAbove        int           // AUTHZ_PLAN_CONFIRM_ABOVE (A132)
	// RecordMoved is told when the effect point moves a record's state, in its transaction: the plans follow it
	// (the entry sets it to the plans module's FollowRecord)
	RecordMoved func(ctx context.Context, tx db.Tx, record, state string) error
}
