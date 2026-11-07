package authz

import (
	"context"
	"fmt"

	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/events"
	"github.com/brickKit/be-sdk-go/v3/evidence"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/projection"
	"github.com/brickKit/be-sdk-go/v3/runtime"
	"github.com/brickKit/be-sdk-go/v3/work"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	accounts "github.com/brickKit/infra-authz/v3/internal/accounts"
	adminrecovery "github.com/brickKit/infra-authz/v3/internal/adminrecovery"
	claim "github.com/brickKit/infra-authz/v3/internal/claim"
	confirmroutes "github.com/brickKit/infra-authz/v3/internal/confirmroutes"
	core "github.com/brickKit/infra-authz/v3/internal/core"
	effectpoint "github.com/brickKit/infra-authz/v3/internal/effectpoint"
	plans "github.com/brickKit/infra-authz/v3/internal/plans"
	restore "github.com/brickKit/infra-authz/v3/internal/restore"
)

// Module is the authorization member: it builds the shared base (core.Base) and registers what each business module
// (internal/) answers; it holds no business itself. The gRPC services forward in services.go.
type Module struct {
	authzv3.UnimplementedViewServiceServer
	authzv3.UnimplementedDefinitionServiceServer
	authzv3.UnimplementedAccountServiceServer
	authzv3.UnimplementedRecoveryServiceServer
	b *core.Base
}

// New builds the module from its runtime: the configuration is checked here, once.
func New(rt *runtime.Runtime) (*Module, error) {
	b := &core.Base{RT: rt, Deployment: rt.Config.String("DEPLOYMENT_ID"), Instance: rt.Config.String("AUTHZ_INSTANCE"),
		RegistryText: func() string { return rt.Config.Secret("AUTHZ_REGISTRY").Value() }}
	if b.Deployment == "" {
		return nil, errs.New(errs.ReasonRequestInvalid, "DEPLOYMENT_ID is required: views and definitions carry it")
	}
	if _, err := core.RegistryNow(b); err != nil {
		return nil, err
	}
	b.SrcHigh, b.SrcRead = rt.Config.Duration("AUTHZ_SOURCE_HIGH"), rt.Config.Duration("AUTHZ_SOURCE_READ")
	if b.SrcHigh <= 0 || b.SrcHigh > core.MaxSourceHigh || b.SrcRead < b.SrcHigh || b.SrcRead > core.MaxSourceRead {
		return nil, errs.New(errs.ReasonRequestInvalid, fmt.Sprintf(
			"AUTHZ_SOURCE_HIGH (%s) is above zero and at most %s; AUTHZ_SOURCE_READ (%s) is no shorter and at most %s",
			b.SrcHigh, core.MaxSourceHigh, b.SrcRead, core.MaxSourceRead))
	}
	if b.Tight = rt.Config.Duration("AUTHZ_T_TIGHT"); b.Tight <= 0 {
		return nil, errs.New(errs.ReasonRequestInvalid, fmt.Sprintf("AUTHZ_T_TIGHT (%s) is above zero", b.Tight))
	}
	if b.MaxDepth = int(rt.Config.Int("AUTHZ_MAX_UNIT_DEPTH")); b.MaxDepth < 1 {
		return nil, errs.New(errs.ReasonRequestInvalid, fmt.Sprintf("AUTHZ_MAX_UNIT_DEPTH (%d) is 1 or more", b.MaxDepth))
	}
	b.PlanMaxAge, b.PlanConfirmAbove = rt.Config.Duration("AUTHZ_PLAN_MAX_AGE"), int(rt.Config.Int("AUTHZ_PLAN_CONFIRM_ABOVE"))
	if b.PlanMaxAge <= 0 || b.PlanConfirmAbove < 0 {
		return nil, errs.New(errs.ReasonRequestInvalid, "AUTHZ_PLAN_MAX_AGE is above zero; AUTHZ_PLAN_CONFIRM_ABOVE is 0 or more")
	}
	iam := rt.Config.String("IAM_COMPONENT")
	conn, ok := rt.GRPCAt(iam, rt.Config.String("IAM_GRPC_URL"))
	if !ok {
		return nil, errs.New(errs.ReasonRequestInvalid, "IAM_GRPC_URL cannot be dialled: the identity member's system surface")
	}
	// an account whose status changed: the closure job keeps the books of what it is a source of
	changed := func(ctx context.Context, tx db.Tx, principal string) error {
		if err := accounts.AccountChanged(b, ctx, tx, principal); err != nil { // its confirmation used; pending confirmation (T9d)
			return err
		}
		if err := effectpoint.IdentitySignal(b, ctx, tx, principal); err != nil { // a freeze or a mark: a disposition (T6c)
			return err
		}
		if err := effectpoint.CloseAfter(b, ctx, tx, "account", principal); err != nil {
			return err
		}
		return effectpoint.JudgeAdmins(b, ctx, tx) // the account of an admin may no longer be active (T6e)
	}
	b.Accounts = &projection.Watermarked{Projection: projection.Projection{Name: core.Accounts, Changed: changed}, DB: rt.DB,
		Source: iam, Stream: core.AccountStream, Deployment: b.Deployment, Freshness: b.SrcHigh, Pull: projection.PullClient{Conn: conn},
		Snapshot: projection.RecordClient{Conn: conn, Stream: core.AccountStream.Name}, Log: rt.Logger}
	// the plans follow a record the effect point moves (an item waiting on it)
	b.RecordMoved = func(ctx context.Context, tx db.Tx, record, state string) error {
		return plans.FollowRecord(b, ctx, tx, record, state)
	}
	return &Module{b: b}, nil
}

// Subscriptions takes the account status stream, every event in position order (P9.19).
func (m *Module) Subscriptions(s *events.Subscriptions) error {
	s.Add(m.b.Accounts.Sub(core.Accounts))
	return nil
}

// Routes registers the user surface, guarded by this member's own view.
func (m *Module) Routes(r *httpx.Routes) error {
	h := m.handler
	// the effect point: changes, tightenings, relinquishments, a key's result, the records
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/changes", Operation: core.OpChange, Handle: h(effectpoint.ChangeHTTP)})
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/tightenings", Operation: core.OpTighten, Handle: h(effectpoint.TightenHTTP)})
	r.Add(httpx.Route{Method: "GET", Path: "/api/authz/changes/:key", Operation: core.OpRelinquish, Handle: h(effectpoint.ChangeByKey)})
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/relinquishments", Operation: core.OpRelinquish, Handle: h(effectpoint.RelinquishHTTP)})
	r.Add(httpx.Route{Method: "GET", Path: "/api/authz/records", Operation: core.OpRead, Handle: h(effectpoint.RecordsHTTP)})
	// confirmations of every kind of target: admitted like a tightening (a stale source's last view does); the handler
	// checks the operation the target needs: a saved widening's confirmation is a change, a tightening's a tightening
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/confirmations", Operation: core.OpTighten, Handle: h(confirmroutes.ConfirmHTTP)})
	r.Add(httpx.Route{Method: "GET", Path: "/api/authz/confirmations/owner-payload", Operation: core.OpTighten,
		Handle: h(confirmroutes.OwnerPayloadHTTP)})
	// security dispositions and the deployment's admin state
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/dispositions", Operation: core.OpDispose, Handle: h(effectpoint.DisposeHTTP)})
	r.Add(httpx.Route{Method: "GET", Path: "/api/authz/dispositions", Operation: core.OpDispRead, Handle: h(effectpoint.DispositionsHTTP)})
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/dispositions/:id/release", Operation: core.OpRelease, Handle: h(effectpoint.ReleaseHTTP)})
	r.Add(httpx.Route{Method: "GET", Path: "/api/authz/admin-state", Operation: core.OpDispRead, Handle: h(effectpoint.AdminStateHTTP)})
	// an account's status change that waits for its confirmation (A134)
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/accounts/:principal/reconfirm", Operation: core.OpChange, Handle: h(accounts.ReconfirmHTTP)})
	// batch plans (A132)
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/plans", Operation: core.OpChange, Handle: h(plans.CreatePlanHTTP)})
	r.Add(httpx.Route{Method: "GET", Path: "/api/authz/plans/:id", Operation: core.OpRead, Handle: h(plans.GetPlanHTTP)})
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/plans/:id/preview", Operation: core.OpChange, Handle: h(plans.PreviewPlanHTTP)})
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/plans/:id/confirm", Operation: core.OpChange, Handle: h(plans.ConfirmPlanHTTP)})
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/plans/:id/cancel", Operation: core.OpChange, Handle: h(plans.CancelPlanHTTP)})
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/plans/:id/items/:item/review", Operation: core.OpChange, Handle: h(plans.ReviewItemHTTP)})
	// the install claim: whoever presents what the claim names; nobody is granted the operation
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/claim", Operation: core.OpClaim, Handle: h(claim.ClaimHTTP)})
	// the administrator recovery: no token (no admin may be left); the recovery key's signature is the credential
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/recovery", Public: true, Handle: h(adminrecovery.RecoveryHTTP)})
	return nil
}

// Jobs declares the member's background work: a saved record's run, the closure and expiry of the effect point, and
// a plan's run and expiry.
func (m *Module) Jobs(j *work.Jobs) error {
	j.Add(work.Job{Name: effectpoint.JobDue, Kind: work.Queue, Effect: work.Local, MaxWait: effectpoint.MaxProcessingWait,
		Handle: m.job(effectpoint.Due)})
	j.Add(work.Job{Name: effectpoint.JobClosure, Kind: work.Queue, Effect: work.Local, Handle: m.job(effectpoint.Closure)})
	j.Add(work.Job{Name: effectpoint.JobExpiry, Kind: work.Queue, Effect: work.Local, Handle: m.job(effectpoint.Expiry)})
	j.Add(work.Job{Name: plans.JobPlan, Kind: work.Queue, Effect: work.Local, MaxWait: effectpoint.MaxProcessingWait,
		Handle: m.job(plans.RunPlan)})
	j.Add(work.Job{Name: plans.JobPlanExpiry, Kind: work.Queue, Effect: work.Local, Handle: m.job(plans.ExpirePlan)})
	return nil
}

// Replays registers the replay of both categories of this member's evidence in a full recovery (evidence.Replayer).
func (m *Module) Replays(r *evidence.Replays) error {
	replay := func(ctx context.Context, tx db.Tx, rec evidence.Replayed) error {
		return restore.Replay(m.b, ctx, tx, rec)
	}
	r.Add("security_tightening", replay)
	r.Add("security_widening", replay)
	return nil
}

// Start writes the member's state row on first start, refuses an instance other than the one installed, runs the
// install claim when the member has no management at all, and keeps the account projection fresh (pulls, alignment)
// for as long as ctx lives.
func (m *Module) Start(ctx context.Context) error {
	if err := m.b.Accounts.Install(ctx); err != nil {
		return err
	}
	go m.b.Accounts.Run(ctx)
	return m.b.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO authz_state (instance) VALUES ($1) ON CONFLICT DO NOTHING", m.b.Instance); err != nil {
			return err
		}
		var instance string
		if err := tx.QueryRow(ctx, "SELECT instance FROM authz_state FOR UPDATE").Scan(&instance); err != nil {
			return err
		}
		if instance != m.b.Instance {
			return errs.New(errs.ReasonRequestInvalid, "AUTHZ_INSTANCE differs from the instance this database was installed with")
		}
		var holdings int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM authz_record WHERE record_type = 'management_holding'`).Scan(&holdings); err != nil {
			return err
		}
		if holdings > 0 {
			return nil
		}
		return claim.RecordClaim(m.b, ctx, tx) // the install claim, consumed by its claimant
	})
}

// handler adapts a module's handler, which takes the shared base first, to what the SDK registers.
func (m *Module) handler(f func(*core.Base, *httpx.Context) error) httpx.Handler {
	return func(c *httpx.Context) error { return f(m.b, c) }
}

// job adapts a module's job handler in the same way.
func (m *Module) job(f func(*core.Base, context.Context, *work.Run) error) func(context.Context, *work.Run) error {
	return func(ctx context.Context, r *work.Run) error { return f(m.b, ctx, r) }
}
