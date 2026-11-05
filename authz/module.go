package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/events"
	"github.com/brickKit/be-sdk-go/v3/grpcx"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/identity"
	"github.com/brickKit/be-sdk-go/v3/projection"
	"github.com/brickKit/be-sdk-go/v3/runtime"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/jackc/pgx/v5"
)

// Module is the authorization member.
type Module struct {
	authzv3.UnimplementedViewServiceServer
	authzv3.UnimplementedDefinitionServiceServer
	rt                   *runtime.Runtime
	deployment, instance string
	registryText         func() string

	mu      sync.Mutex
	regText string
	reg     registry

	// accounts is the identity member's account status, kept with its watermark; srcHigh and srcRead are D_src_high
	// and D_src_read, tight is T_tight (security 03)
	accounts                *projection.Watermarked
	srcHigh, srcRead, tight time.Duration
	maxDepth                int // AUTHZ_MAX_UNIT_DEPTH (A131)
	planMaxAge              time.Duration
	planConfirmAbove        int // AUTHZ_PLAN_MAX_AGE, AUTHZ_PLAN_CONFIRM_ABOVE (A132)
}

// New builds the module from its runtime.
func New(rt *runtime.Runtime) (*Module, error) {
	m := &Module{rt: rt, deployment: rt.Config.String("DEPLOYMENT_ID"), instance: rt.Config.String("AUTHZ_INSTANCE"),
		registryText: func() string { return rt.Config.Secret("AUTHZ_REGISTRY").Value() }}
	if m.deployment == "" {
		return nil, errs.New(errs.ReasonRequestInvalid, "DEPLOYMENT_ID is required: views and definitions carry it")
	}
	if _, err := m.registry(); err != nil {
		return nil, err
	}
	m.srcHigh, m.srcRead = rt.Config.Duration("AUTHZ_SOURCE_HIGH"), rt.Config.Duration("AUTHZ_SOURCE_READ")
	if m.srcHigh <= 0 || m.srcHigh > MaxSourceHigh || m.srcRead < m.srcHigh || m.srcRead > MaxSourceRead {
		return nil, errs.New(errs.ReasonRequestInvalid, fmt.Sprintf(
			"AUTHZ_SOURCE_HIGH (%s) is above zero and at most %s; AUTHZ_SOURCE_READ (%s) is no shorter and at most %s",
			m.srcHigh, MaxSourceHigh, m.srcRead, MaxSourceRead))
	}
	if m.tight = rt.Config.Duration("AUTHZ_T_TIGHT"); m.tight <= 0 {
		return nil, errs.New(errs.ReasonRequestInvalid, fmt.Sprintf("AUTHZ_T_TIGHT (%s) is above zero", m.tight))
	}
	if m.maxDepth = int(rt.Config.Int("AUTHZ_MAX_UNIT_DEPTH")); m.maxDepth < 1 {
		return nil, errs.New(errs.ReasonRequestInvalid, fmt.Sprintf("AUTHZ_MAX_UNIT_DEPTH (%d) is 1 or more", m.maxDepth))
	}
	m.planMaxAge, m.planConfirmAbove = rt.Config.Duration("AUTHZ_PLAN_MAX_AGE"), int(rt.Config.Int("AUTHZ_PLAN_CONFIRM_ABOVE"))
	if m.planMaxAge <= 0 || m.planConfirmAbove < 0 {
		return nil, errs.New(errs.ReasonRequestInvalid, "AUTHZ_PLAN_MAX_AGE is above zero; AUTHZ_PLAN_CONFIRM_ABOVE is 0 or more")
	}
	iam := rt.Config.String("IAM_COMPONENT")
	conn, ok := rt.GRPCAt(iam, rt.Config.String("IAM_GRPC_URL"))
	if !ok {
		return nil, errs.New(errs.ReasonRequestInvalid, "IAM_GRPC_URL cannot be dialled: the identity member's system surface")
	}
	// an account whose status changed: the closure job keeps the books of what it is a source of
	changed := func(ctx context.Context, tx db.Tx, principal string) error {
		if err := m.identitySignal(ctx, tx, principal); err != nil { // a freeze or a mark: a disposition (T6c)
			return err
		}
		if err := m.closeAfter(ctx, tx, "account", principal); err != nil {
			return err
		}
		return m.judgeAdmins(ctx, tx) // the account of an admin may no longer be active (T6e)
	}
	m.accounts = &projection.Watermarked{Projection: projection.Projection{Name: Accounts, Changed: changed}, DB: rt.DB, Source: iam,
		Stream: AccountStream, Deployment: m.deployment, Freshness: m.srcHigh, Pull: projection.PullClient{Conn: conn},
		Snapshot: projection.RecordClient{Conn: conn, Stream: AccountStream.Name}, Log: rt.Logger}
	return m, nil
}

// Subscriptions takes the account status stream, every event in position order (P9.19).
func (m *Module) Subscriptions(s *events.Subscriptions) error {
	s.Add(m.accounts.Sub(Accounts))
	return nil
}

// registry parses AUTHZ_REGISTRY again only when it changed (the SDK re-reads the file).
func (m *Module) registry() (registry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t := m.registryText(); t != m.regText || m.reg == nil {
		r, err := parseRegistry(t)
		if err != nil {
			return nil, err
		}
		m.regText, m.reg = t, r
	}
	return m.reg, nil
}

// Services registers the family contract's two services; every component of the deployment calls them.
func (m *Module) Services(s *grpcx.Services) error {
	s.Register(&authzv3.ViewService_ServiceDesc, m, map[string]grpcx.Method{
		"Verify": {Operation: OpVerify, Callers: []string{grpcx.AnyComponent}}})
	s.Register(&authzv3.DefinitionService_ServiceDesc, m, map[string]grpcx.Method{
		"Submit": {Operation: OpSubmit, Callers: []string{grpcx.AnyComponent}}})
	return nil
}

// Routes registers the user surface: the effect point and the records, guarded by this member's own view.
func (m *Module) Routes(r *httpx.Routes) error {
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/changes", Operation: OpChange, Handle: m.changeHTTP})
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/tightenings", Operation: OpTighten, Handle: m.tightenHTTP})
	// admitted like a tightening (a stale source's last view does); the handler checks the operation the target needs:
	// a saved widening's confirmation is a change, a tightening's a tightening
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/confirmations", Operation: OpTighten, Handle: m.confirmHTTP})
	r.Add(httpx.Route{Method: "GET", Path: "/api/authz/confirmations/owner-payload", Operation: OpTighten, Handle: m.ownerPayloadHTTP})
	r.Add(httpx.Route{Method: "GET", Path: "/api/authz/changes/:key", Operation: OpRelinquish, Handle: m.changeByKey})
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/relinquishments", Operation: OpRelinquish, Handle: m.relinquishHTTP})
	r.Add(httpx.Route{Method: "GET", Path: "/api/authz/records", Operation: OpRead, Handle: m.recordsHTTP})
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/dispositions", Operation: OpDispose, Handle: m.disposeHTTP})
	r.Add(httpx.Route{Method: "GET", Path: "/api/authz/dispositions", Operation: OpDispRead, Handle: m.dispositionsHTTP})
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/dispositions/:id/release", Operation: OpRelease, Handle: m.releaseHTTP})
	r.Add(httpx.Route{Method: "GET", Path: "/api/authz/admin-state", Operation: OpDispRead, Handle: m.adminStateHTTP})
	// batch plans (planhttp.go, A132)
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/plans", Operation: OpChange, Handle: m.createPlanHTTP})
	r.Add(httpx.Route{Method: "GET", Path: "/api/authz/plans/:id", Operation: OpRead, Handle: m.getPlanHTTP})
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/plans/:id/preview", Operation: OpChange, Handle: m.previewPlanHTTP})
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/plans/:id/confirm", Operation: OpChange, Handle: m.confirmPlanHTTP})
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/plans/:id/cancel", Operation: OpChange, Handle: m.cancelPlanHTTP})
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/plans/:id/items/:item/review", Operation: OpChange, Handle: m.reviewItemHTTP})
	// the install claim: whoever presents what the claim names (claim.go); nobody is granted the operation
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/claim", Operation: OpClaim, Handle: m.claimHTTP})
	// the administrator recovery: no token (no admin may be left); the recovery key's signature is the credential
	r.Add(httpx.Route{Method: "POST", Path: "/api/authz/recovery", Public: true, Handle: m.recoveryHTTP})
	return nil
}

// changeHTTP takes widenings and neutral changes; a tightening goes to tightenHTTP, under its own operation.
func (m *Module) changeHTTP(c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	var in request
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	if in.Direction == Tighten {
		return errs.New(errs.ReasonRequestInvalid, "a tightening goes to POST /api/authz/tightenings ("+OpTighten+")")
	}
	facts, err := m.holderFacts(c.Ctx(), in)
	if err != nil {
		return err
	}
	ctx, _, err := s.Check(c.Ctx(), OpChange, facts)
	if err != nil {
		return err
	}
	u, _ := identity.UserFrom(ctx)
	res, err := m.change(ctx, u.Subject, in)
	if err != nil {
		return err
	}
	return answer(c, res)
}

// tightenHTTP takes a tightening of an existing record: a revocation, a narrowing, or ending one not yet effective.
// The operation is tightening_only: admitted on a stale source's last view (P8.29), the requester judged at the effect
// point by the last applied facts within T_tight, with a second person beyond (security 03, A125).
func (m *Module) tightenHTTP(c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	var in request
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	if in.Direction != Tighten || in.Target == "" {
		return errs.New(errs.ReasonRequestInvalid, "a tightening is direction tighten on its target")
	}
	facts, err := m.holderFacts(c.Ctx(), in)
	if err != nil {
		return err
	}
	ctx, _, err := s.Check(c.Ctx(), OpTighten, facts)
	if err != nil {
		return err
	}
	u, _ := identity.UserFrom(ctx)
	res, err := m.change(ctx, u.Subject, in)
	if err != nil {
		return err
	}
	return answer(c, res)
}

// relinquishHTTP is a principal ending its own grant or holding (D82): a whole record, the requester its grantee or
// holder; the effect point checks the rest as for any tightening.
func (m *Module) relinquishHTTP(c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	var in request
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	if in.Direction != Tighten || in.Target == "" || in.Termination != "" || len(in.Candidate) > 0 {
		return errs.New(errs.ReasonRequestInvalid, "a relinquishment ends one whole record: direction tighten and its target, nothing else")
	}
	facts, err := m.holderFacts(c.Ctx(), in)
	if err != nil {
		return err
	}
	ctx, _, err := s.Check(c.Ctx(), OpRelinquish, facts) // another's record: not visible, 404
	if err != nil {
		return err
	}
	u, _ := identity.UserFrom(ctx)
	res, err := m.changeAs(ctx, u.Subject, in, true)
	if err != nil {
		return err
	}
	return answer(c, res)
}

// holderFacts are a change's facts for the holder dimension: whose its target is, or whose its candidate would be.
func (m *Module) holderFacts(ctx context.Context, in request) (sdkauthz.Facts, error) {
	var holder string
	switch {
	case in.Target != "":
		if !uuidText.MatchString(in.Target) {
			return sdkauthz.Facts{Holder: {State: "null"}}, nil
		}
		err := m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
			var h *string
			err := tx.QueryRow(ctx, "SELECT holder FROM authz_record WHERE id = $1", in.Target).Scan(&h)
			if errors.Is(err, pgx.ErrNoRows) || h == nil {
				return nil
			}
			holder = *h
			return err
		})
		if err != nil {
			return nil, err
		}
	case len(in.Candidate) > 0:
		var b struct {
			Grantee string `json:"grantee"`
			Holder  string `json:"holder"`
		}
		_ = json.Unmarshal(in.Candidate, &b)
		holder = b.Grantee + b.Holder
	}
	if holder == "" {
		return sdkauthz.Facts{Holder: {State: "null"}}, nil // a unit, a role revision, or no such record: nobody's
	}
	return sdkauthz.Facts{Holder: {State: "value", Value: holder}}, nil
}

// answer is a change result on the user surface: a rejection as its error; processing, awaiting confirmation and
// scheduled are accepted for later (202, security 09a); applied and a kept hold are done (200).
func answer(c *httpx.Context, res changeResult) error {
	switch res.Outcome {
	case "rejected":
		return errs.New(res.Reason, res.Detail).With("change_key", res.ChangeKey)
	case "processing", "awaiting_confirmation", "scheduled":
		return c.JSON(202, res)
	}
	return c.JSON(200, res)
}

// changeByKey answers a query by change key (security 08: when a result is unknown, ask, do not submit again).
func (m *Module) changeByKey(c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	u, _ := identity.UserFrom(c.Ctx())
	// the key is in the caller's own namespace: those who may change or tighten records, or relinquish their own, may ask
	own := sdkauthz.Facts{Holder: {State: "value", Value: u.Subject}}
	var ctx context.Context
	var err error
	for _, op := range []string{OpChange, OpTighten, OpRelinquish} {
		if ctx, _, err = s.Check(c.Ctx(), op, own); err == nil {
			break
		}
	}
	if err != nil {
		return err
	}
	key := c.Param("key")
	res := changeResult{ChangeKey: key, Outcome: "unbound"}
	err = m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var bound []byte
		err := tx.QueryRow(ctx, "SELECT result FROM authz_change WHERE requested_by = $1 AND change_key = $2",
			u.Subject, key).Scan(&bound)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err == nil {
			err = json.Unmarshal(bound, &res)
		}
		if err == nil {
			res, err = current(ctx, tx, res)
		}
		return err
	})
	if err != nil {
		return err
	}
	return c.JSON(200, res)
}

func (m *Module) recordsHTTP(c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	ctx, plan, err := s.List(c.Ctx(), OpRead, "r", 1) // $1 is the types; only the records the caller may see (its own, D82, or all)
	if err != nil {
		return err
	}
	types := []string{"management_unit", "management_holding", "role_revision", "grant"}
	if t := c.Query("type"); t != "" {
		types = []string{t}
	}
	var out []map[string]any
	err = m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT r.id::text, r.record_type, r.revision, r.body FROM authz_record r
			WHERE r.state = 'active' AND r.record_type = ANY($1)
				AND (r.valid_from IS NULL OR r.valid_from <= now()) AND (r.valid_until IS NULL OR r.valid_until > now())
				AND (`+plan.Where+`) ORDER BY r.created_at, r.id`, append([]any{types}, plan.Args...)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r record
			if err := rows.Scan(&r.ID, &r.Type, &r.Revision, &r.Body); err != nil {
				return err
			}
			out = append(out, map[string]any{"id": r.ID, "record_type": r.Type, "revision": r.Revision, "body": r.Body})
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	return c.JSON(200, map[string]any{"records": out})
}

// Start writes the member's state row on first start, refuses an instance other than the one installed, runs the
// install claim when the member has no management at all, and keeps the account projection fresh (pulls, alignment)
// for as long as ctx lives.
func (m *Module) Start(ctx context.Context) error {
	if err := m.accounts.Install(ctx); err != nil {
		return err
	}
	go m.accounts.Run(ctx)
	return m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO authz_state (instance) VALUES ($1) ON CONFLICT DO NOTHING", m.instance); err != nil {
			return err
		}
		var instance string
		if err := tx.QueryRow(ctx, "SELECT instance FROM authz_state FOR UPDATE").Scan(&instance); err != nil {
			return err
		}
		if instance != m.instance {
			return errs.New(errs.ReasonRequestInvalid, "AUTHZ_INSTANCE differs from the instance this database was installed with")
		}
		var holdings int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM authz_record WHERE record_type = 'management_holding'`).Scan(&holdings); err != nil {
			return err
		}
		if holdings > 0 {
			return nil
		}
		return m.recordClaim(ctx, tx) // the install claim, consumed by its claimant (claim.go)
	})
}
