package authz

import (
	"context"

	"github.com/brickKit/be-sdk-go/v3/grpcx"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	accounts "github.com/brickKit/infra-authz/v3/internal/accounts"
	core "github.com/brickKit/infra-authz/v3/internal/core"
	definitions "github.com/brickKit/infra-authz/v3/internal/definitions"
	restore "github.com/brickKit/infra-authz/v3/internal/restore"
	view "github.com/brickKit/infra-authz/v3/internal/view"
)

// Services registers the family contract's services: every component of the deployment calls the first two, the
// identity member the third, the recovery tool the fourth.
func (m *Module) Services(s *grpcx.Services) error {
	s.Register(&authzv3.ViewService_ServiceDesc, m, map[string]grpcx.Method{
		"Verify": {Operation: core.OpVerify, Callers: []string{grpcx.AnyComponent}}})
	s.Register(&authzv3.DefinitionService_ServiceDesc, m, map[string]grpcx.Method{
		"Submit": {Operation: core.OpSubmit, Callers: []string{grpcx.AnyComponent}}})
	// the identity member asks before it changes an account's status (T9c, A134)
	s.Register(&authzv3.AccountService_ServiceDesc, m, map[string]grpcx.Method{
		"CheckAccountChange": {Operation: core.OpAccountCheck, Callers: []string{m.b.RT.Config.String("IAM_COMPONENT")}}})
	// a full recovery's 6.4-6.5 after the replay (A142): the replay's operation, the tool only
	tool := []string{restore.RecoveryTool}
	s.Register(&authzv3.RecoveryService_ServiceDesc, m, map[string]grpcx.Method{
		"Sources":        {Operation: core.OpReplay, Callers: tool},
		"ReplayDeferred": {Operation: core.OpReplay, Callers: tool, Orchestration: true},
		"Check":          {Operation: core.OpReplay, Callers: tool, Orchestration: true}})
	return nil
}

// Verify answers a component's view (the view module).
func (m *Module) Verify(ctx context.Context, in *authzv3.VerifyRequest) (*authzv3.VerifyResponse, error) {
	return view.Verify(m.b, ctx, in)
}

// Submit takes a component's definitions (the definitions module).
func (m *Module) Submit(ctx context.Context, in *authzv3.SubmitRequest) (*authzv3.SubmitResponse, error) {
	return definitions.Submit(m.b, ctx, in)
}

// CheckAccountChange answers whether an account's status change needs a confirmation (the accounts module).
func (m *Module) CheckAccountChange(ctx context.Context, in *authzv3.CheckAccountChangeRequest) (*authzv3.CheckAccountChangeResponse, error) {
	return accounts.CheckAccountChange(m.b, ctx, in)
}

// Sources, ReplayDeferred and Check are a full recovery's 6.4-6.5 (the restore module).
func (m *Module) Sources(ctx context.Context, in *authzv3.SourcesRequest) (*authzv3.SourcesResponse, error) {
	return restore.Sources(m.b, ctx, in)
}

func (m *Module) ReplayDeferred(ctx context.Context, in *authzv3.ReplayDeferredRequest) (*authzv3.ReplayDeferredResponse, error) {
	return restore.ReplayDeferred(m.b, ctx, in)
}

func (m *Module) Check(ctx context.Context, in *authzv3.CheckRequest) (*authzv3.CheckResponse, error) {
	return restore.Check(m.b, ctx, in)
}
