//go:build integration

package itest

import (
	"context"
	"testing"
	"time"

	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestSystemMethodsAnswerTheirReason: a refusal on the system surface reaches the caller as its own reason, not as
// INTERNAL (a handler returns the errs error itself; grpcx turns it into a status). Found while writing infra/audit's
// evidence store (item 4 T4d).
func TestSystemMethodsAnswerTheirReason(t *testing.T) {
	e := startE2E(t)
	ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
	defer cancel()
	_, err := authzv3.NewDefinitionServiceClient(dial(t, e.w, "demo/orders")).Submit(ctx,
		&authzv3.SubmitRequest{Component: "demo/other", Version: "1.0.0"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "another component's definitions: %v", err)
	_, err = authzv3.NewAccountServiceClient(dial(t, e.w, iamID)).CheckAccountChange(ctx, &authzv3.CheckAccountChangeRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "required fields missing: %v", err)
}
