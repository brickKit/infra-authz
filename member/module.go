package member

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/brickKit/be-sdk-go/v3/audit"
	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/grpcx"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/identity"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/brickKit/be-sdk-go/v3/runtime"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
)

// Module is the authorization member.
type Module struct {
	authzv3.UnimplementedViewServiceServer
	authzv3.UnimplementedDefinitionServiceServer
	rt                              *runtime.Runtime
	deployment, instance, bootstrap string
	registryText                    func() string

	mu      sync.Mutex
	regText string
	reg     registry
}

// New builds the module from its runtime.
func New(rt *runtime.Runtime) (*Module, error) {
	m := &Module{rt: rt, deployment: rt.Config.String("DEPLOYMENT_ID"), instance: rt.Config.String("AUTHZ_INSTANCE"),
		bootstrap:    rt.Config.String("AUTHZ_BOOTSTRAP_ADMIN"),
		registryText: func() string { return rt.Config.Secret("AUTHZ_REGISTRY").Value() }}
	if m.deployment == "" {
		return nil, errs.New(errs.ReasonRequestInvalid, "DEPLOYMENT_ID is required: views and definitions carry it")
	}
	if _, err := m.registry(); err != nil {
		return nil, err
	}
	return m, nil
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
	r.Add(httpx.Route{Method: "GET", Path: "/api/authz/records", Operation: OpRead, Handle: m.recordsHTTP})
	return nil
}

func (m *Module) changeHTTP(c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	ctx, _, err := s.Check(c.Ctx(), OpChange, sdkauthz.Facts{})
	if err != nil {
		return err
	}
	u, _ := identity.UserFrom(ctx)
	var in change
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	res, err := m.apply(ctx, u.Subject, in)
	if err != nil {
		return err
	}
	if res.Outcome == "rejected" {
		return errs.New(res.Reason, res.Detail).With("change_key", res.ChangeKey)
	}
	return c.JSON(200, res)
}

func (m *Module) recordsHTTP(c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	ctx, _, err := s.Check(c.Ctx(), OpRead, sdkauthz.Facts{})
	if err != nil {
		return err
	}
	types := []string{"management_unit", "management_holding", "role_revision", "grant"}
	if t := c.Query("type"); t != "" {
		types = []string{t}
	}
	var out []map[string]any
	err = m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		recs, err := active(ctx, tx, types...)
		for _, r := range recs {
			out = append(out, map[string]any{"id": r.ID, "record_type": r.Type, "revision": r.Revision, "body": r.Body})
		}
		return err
	})
	if err != nil {
		return err
	}
	return c.JSON(200, map[string]any{"records": out})
}

// Start writes the member's state row on first start, refuses an instance other than the one installed, and runs
// the install claim when the member has no management at all.
func (m *Module) Start(ctx context.Context) error {
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
		if holdings > 0 || m.bootstrap == "" {
			return nil
		}
		return m.claim(ctx, tx)
	})
}

// claim is the install claim, simplified (security 08, "安装认领"): the configured principal becomes the first
// authorization admin over a root unit, with a grant to read and change the security records.
func (m *Module) claim(ctx context.Context, tx db.Tx) error {
	root, holding, grant := ids.New().String(), ids.New().String(), ids.New().String()
	from := canon.Time(time.Now().Add(-time.Minute))
	seg := func(op string) sdkauthz.Segment {
		return sdkauthz.Segment{ResourceType: Records, Operation: op, Atoms: map[string]sdkauthz.Atom{},
			ReadFields: []string{"body", "id", "record_type", "state"}, Valid: sdkauthz.Window{From: from}}
	}
	write := func(id, typ string, body any) error {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO authz_record (id, record_type, state, body, requested_by) VALUES ($1, $2, 'active', $3, $4)`,
			id, typ, b, ID)
		return err
	}
	for _, w := range []struct {
		id, typ string
		body    any
	}{
		{root, "management_unit", unitBody{Name: "deployment", Root: true}},
		{holding, "management_holding", holdingBody{Unit: root, Holder: m.bootstrap, SystemRole: "authorization_admin"}},
		{grant, "grant", grantBody{Grantee: m.bootstrap, Segments: []sdkauthz.Segment{seg(OpRead), seg(OpChange)},
			GovernanceUnit: root, IssuedBy: ID}},
	} {
		if err := write(w.id, w.typ, w.body); err != nil {
			return err
		}
	}
	if err := advance(ctx, tx); err != nil {
		return err
	}
	m.rt.Logger.Warn("install claim: the configured principal is the first authorization admin", "principal", m.bootstrap)
	_, err := m.rt.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: OpChange,
		Outcome: audit.Succeeded, Actor: ID, Target: map[string]any{"type": "management_holding", "id": holding},
		Changes: map[string]any{"action": "install_claim", "holder": m.bootstrap}})
	return err
}
