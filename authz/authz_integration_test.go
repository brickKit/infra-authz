//go:build integration

package authz

// The member against PostgreSQL, over its real surfaces: a component's definitions submitted over mTLS, the views
// it issues opened by the SDK's own client, changes at the effect point by users with tokens of the test deployment
// (be-sdk-go's sectest), and the member guarding its own user surface with its own view. Needs AUTHZ_IT_PG_PASSWORD
// (the postgres superuser of be-postgres); missing, it fails. The member listens on 28223 (user) and 9223 (system).
// Run: go test -tags integration ./member/

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/config"
	"github.com/brickKit/be-sdk-go/v3/events/pgqueue"
	"github.com/brickKit/be-sdk-go/v3/launcher"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	itPort    = "28223"
	itBase    = "http://localhost:" + itPort
	itSystem  = "localhost:9223"
	itSchema  = "authz_it"
	itDB      = "brickkit_test_db"
	carol     = "0190f3a1-0000-7000-8000-0000000000c3"
	dave      = "0190f3a1-0000-7000-8000-0000000000d4"
	eve       = "0190f3a1-0000-7000-8000-0000000000e5"
	busSchema = "authz_it_bus"
)

// orders is a component with one dimension, to grant within limits.
var orders = &sdkauthz.Definitions{Component: "demo/orders",
	Resources: []sdkauthz.Resource{{Type: "demo.order", ViewOperation: "demo.order.read",
		Dimensions: map[string]sdkauthz.Dimension{"region": {Kind: sdkauthz.ValueSet, Column: "region"}},
		Fields:     map[string]sdkauthz.Field{"id": {Class: sdkauthz.Ordinary}, "total": {Class: sdkauthz.Ordinary}}}},
	Operations: []sdkauthz.Operation{{Key: "demo.order.read", ResourceType: "demo.order", Purpose: "read", RiskClass: "low"}}}

const registryTSV = "kind\tkey\towner_component\n" +
	"resource_type\tinfra.authz.security_record\tinfra/authz\nresource_type\tinfra.authz.system\tinfra/authz\n" +
	"permission\tinfra.authz.security_record.read\tinfra/authz\npermission\tinfra.authz.security_record.change\tinfra/authz\n" +
	"permission\tinfra.authz.security_record.tighten\tinfra/authz\n" +
	"permission\tinfra.authz.security_record.relinquish\tinfra/authz\n" +
	"permission\tinfra.authz.system.read\tinfra/authz\npermission\tinfra.authz.system.verify\tinfra/authz\n" +
	"permission\tinfra.authz.system.submit\tinfra/authz\n" +
	"resource_type\tdemo.order\tdemo/orders\npermission\tdemo.order.read\tdemo/orders\n" +
	"resource_type\tdemo.invoice\tdemo/invoices\npermission\tdemo.invoice.read\tdemo/invoices\n" +
	"permission\tdemo.invoice.export\tdemo/invoices\n"

// invoices submits its definitions late in the test: a grant naming its resource type waits for them (D77).
var invoices = &sdkauthz.Definitions{Component: "demo/invoices",
	Resources: []sdkauthz.Resource{{Type: "demo.invoice", ViewOperation: "demo.invoice.read",
		Dimensions: map[string]sdkauthz.Dimension{}, Fields: map[string]sdkauthz.Field{"id": {Class: sdkauthz.Ordinary}}}},
	Operations: []sdkauthz.Operation{{Key: "demo.invoice.read", ResourceType: "demo.invoice", Purpose: "read", RiskClass: "low"},
		{Key: "demo.invoice.export", ResourceType: "demo.invoice", Purpose: "export", RiskClass: "low"}}}

func region(v ...string) map[string]sdkauthz.Atom {
	return map[string]sdkauthz.Atom{"region": {Kind: "in", Values: v}}
}

func orderSeg(atoms map[string]sdkauthz.Atom) sdkauthz.Segment {
	return sdkauthz.Segment{ResourceType: "demo.order", Operation: "demo.order.read", Atoms: atoms,
		ReadFields: []string{"id", "total"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}}
}

func TestMemberEndToEnd(t *testing.T) {
	e := startE2E(t)
	e.definitionsAndViews()
	e.effectPoint()
	e.lifecycle()
	testScheduled(t, e.w, e.admin, e.root, e.east, e.inView)
	testNeutral(t, e.w, e.admin, e.root, e.east)
	testEffective(t, e.w, e.admin, e.root, e.segmentsOf)
	testSources(t, e.w, e.admin, e.root, e.segmentsOf)
	testUncomputable(t, e.w, e.admin, e.root, e.segmentsOf)
	testRelinquish(t, e.w, e.admin, e.root)
	testConfirmations(t, e.w, e.admin, e.root)
	e.identity()
	e.staleTightening()
	e.coolingOff()
	e.audited()
}

// e2e is one end-to-end run: the test deployment, the database, the stand-in identity member, the member, and
// demo/orders' view as the test holds it (the shard, its digest, the last subjects seen).
type e2e struct {
	t                  *testing.T
	ctx                context.Context
	w                  *sectest.World
	admin              *pgx.Conn
	iam                *iamModule
	stopIAM            func()
	pgPassword, busURL string
	src                sdkauthz.GRPCSource
	held               sdkauthz.Held
	subjects           map[string]sdkauthz.SubjectEntry
	root, east         string
}

// verify opens demo/orders' view through the SDK's own client.
func (e *e2e) verify(held ...sdkauthz.Held) sdkauthz.VerifyAnswer {
	ans, err := e.src.Verify(e.ctx, sdkauthz.VerifyRequest{Component: "demo/orders", Nonce: "n1", Held: held})
	require.NoError(e.t, err, "the view opens: canonical, its digest, the schema")
	require.Len(e.t, ans.Shards, 1)
	return ans
}

// segmentsOf verifies demo/orders' view and returns a principal's segments in the last view seen.
func (e *e2e) segmentsOf(p string) []sdkauthz.Segment {
	ans := e.verify(e.held)
	if ans.Shards[0].Status == "changed" {
		e.held.Digest, e.subjects = ans.Shards[0].View.Digest, ans.Shards[0].View.Subjects
	}
	return e.subjects[p].Segments
}

// inView: the principal has a segment in demo/orders' view.
func (e *e2e) inView(p string) bool { return len(e.segmentsOf(p)) > 0 }

// startE2E migrates and starts the member against PostgreSQL, the stand-in identity member and a bus of its own,
// and waits until it verifies its own view.
func startE2E(t *testing.T) *e2e {
	pgPassword := os.Getenv("AUTHZ_IT_PG_PASSWORD")
	if pgPassword == "" {
		t.Fatal("AUTHZ_IT_PG_PASSWORD is not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, "postgres://postgres:"+url.QueryEscape(pgPassword)+"@localhost:5432/"+itDB+"?sslmode=disable")
	require.NoError(t, err)
	t.Cleanup(func() { admin.Close(ctx) })
	itAdmin = admin
	_, err = admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+itSchema+" CASCADE; CREATE SCHEMA "+itSchema+
		"; DROP SCHEMA IF EXISTS "+iamSchema+" CASCADE; CREATE SCHEMA "+iamSchema+"; DROP SCHEMA IF EXISTS "+busSchema+" CASCADE; CREATE SCHEMA "+busSchema)
	require.NoError(t, err)
	// the bus in its own schema, new for every run: a stream on a shared bus would bring events of earlier runs'
	// deployments, and those block the source (P9.11)
	busURL := "pgqueue://postgres:" + url.QueryEscape(pgPassword) + "@localhost:5432/" + itDB + "?schema=" + busSchema
	require.NoError(t, pgqueue.Migrate(ctx, busURL, slog.New(slog.NewTextHandler(io.Discard, nil))))

	w := sectest.New(t)
	portFree(t, itPort, itSystem)
	iam, stopIAM := startIAM(t, w, pgPassword, busURL, true)
	for _, p := range []string{sectest.Alice, sectest.Bob, carol, dave, eve} {
		require.NoError(t, iam.set(ctx, p, "active", 1))
	}
	env := w.Env(t, ID)
	for k, v := range map[string]string{"COMPONENT_ID": ID, "COMPONENT_VERSION": Version, "PORT": itPort, "STOP_DRAIN_DELAY": "50ms",
		"PG_HOST": "localhost", "PG_DATABASE": itDB, "PG_USER": "postgres", "PG_PASSWORD": pgPassword, "PG_SCHEMA": itSchema,
		"PG_OWNER_USER": "postgres", "PG_OWNER_PASSWORD": pgPassword, "AUTHZ_INSTANCE": "authz-it-instance",
		"AUTHZ_REGISTRY": registryTSV, "AUTHZ_BOOTSTRAP_ADMIN": sectest.Alice, "BUS_URL": busURL,
		"IAM_GRPC_URL": "http://" + iamSystem, "IAM_COMPONENT": iamID, "AUTHZ_SOURCE_HIGH": "3s", "AUTHZ_SOURCE_READ": "6s",
		"AUTHZ_T_TIGHT":   itTight.String(),
		"AUTHZ_OWNER_KEY": ownerPublicPEM(t),
		"AUTHZ_GRPC_URL":  "http://" + itSystem} { // the member guards its own user surface with its own view
		env[k] = v
	}
	var logs bytes.Buffer
	run := func(args ...string) int {
		return launcher.Run(ctx, Definition(), launcher.Options{Args: args, Stdout: &logs, Stderr: &logs,
			Env: config.Env{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }, Read: os.ReadFile}})
	}
	require.Equal(t, launcher.ExitOK, run("migrate"), logs.String())
	sctx, stop := context.WithCancel(ctx)
	done := make(chan int, 1)
	go func() {
		done <- launcher.Run(sctx, Definition(), launcher.Options{Stdout: &logs, Stderr: &logs,
			Env: config.Env{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }, Read: os.ReadFile}})
	}()
	t.Cleanup(func() { stop(); <-done })
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(logs.String())
		}
	})
	ready := assert.Eventually(t, func() bool {
		r, err := http.Get(itBase + "/readyz")
		if err == nil {
			r.Body.Close()
		}
		return err == nil && r.StatusCode == 200
	}, 15*time.Second, 100*time.Millisecond, "the member submits to itself and verifies its own view")
	require.True(t, ready)
	waitForView(t, w, sectest.Alice) // the account projection aligned with the identity member: views renew

	return &e2e{t: t, ctx: ctx, w: w, admin: admin, iam: iam, stopIAM: stopIAM, pgPassword: pgPassword, busURL: busURL}
}

// definitionsAndViews: a component's definitions over mTLS, then its view through the SDK's own client.
func (e *e2e) definitionsAndViews() {
	t, w, ctx := e.t, e.w, e.ctx
	var err error
	// a component over mTLS: its definitions, then its view through the SDK's own client
	conn := dial(t, w, "demo/orders")
	defs := authzv3.NewDefinitionServiceClient(conn)
	require.NoError(t, orders.Validate())
	require.NoError(t, orders.Submit(ctx, defs, w.Deployment, "3.0.0"), "accepted")
	require.NoError(t, orders.Submit(ctx, defs, w.Deployment, "3.0.0"), "the same set again: accepted")
	changed := *orders
	changed.Operations = append([]sdkauthz.Operation{}, orders.Operations...)
	changed.Operations[0].RiskClass = "high"
	require.NoError(t, changed.Validate())
	var rej *sdkauthz.RejectedError
	assert.ErrorAs(t, changed.Submit(ctx, defs, w.Deployment, "3.0.0"), &rej)
	assert.Contains(t, rej.Error(), "DEFINITION_VERSION_CONFLICT")
	foreign := &sdkauthz.Definitions{Component: "demo/orders", Resources: []sdkauthz.Resource{{Type: "infra.authz.system",
		ViewOperation: "infra.authz.system.read", Dimensions: map[string]sdkauthz.Dimension{}}},
		Operations: []sdkauthz.Operation{{Key: "infra.authz.system.read", ResourceType: "infra.authz.system", Purpose: "read", RiskClass: "low"}}}
	require.NoError(t, foreign.Validate())
	assert.ErrorAs(t, foreign.Submit(ctx, defs, w.Deployment, "3.0.1"), &rej)
	assert.Contains(t, rej.Error(), "DEFINITION_OWNER_MISMATCH", "another component's resource type and keys")
	_, err = defs.Submit(ctx, &authzv3.SubmitRequest{Component: "erp/sales", Version: "1"})
	assert.Error(t, err, "a component submits only for itself")

	e.src = sdkauthz.GRPCSource{Conn: conn}
	verify := e.verify
	ans := verify()
	assert.Equal(t, "changed", ans.Shards[0].Status)
	assert.Equal(t, "authz-it-instance", ans.Instance)
	assert.Equal(t, []string{"demo.order"}, ans.Shards[0].View.Applicability)
	held := sdkauthz.Held{Shard: ans.Shards[0].Shard, Digest: ans.Shards[0].View.Digest}
	assert.Equal(t, "unchanged", verify(held).Shards[0].Status)

	e.held = held
}

// effectPoint: the effect point's first story: units, holdings, grants within and beyond a limit, keys, revocation,
// the last admin.
func (e *e2e) effectPoint() {
	t, w, ctx, verify, held := e.t, e.w, e.ctx, e.verify, e.held
	defer func() { e.held = held }()
	// the effect point: Alice (the install claim) sets up a unit limited to the east and lets Bob manage it
	units := listRecords(t, w, sectest.Alice, "management_unit")
	require.Len(t, units, 1)
	root := units[0]["id"].(string)

	// a grant naming a resource type whose definitions have not arrived: retryable, and the change key stays free, so
	// the same key takes effect once they are accepted (D77; a member is ready before its definitions are accepted)
	invoiceGrant := grantReq("p1", root, sectest.Bob, []sdkauthz.Segment{{ResourceType: "demo.invoice", Operation: "demo.invoice.read", Atoms: map[string]sdkauthz.Atom{},
		ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}}})
	// a resource type the registry does not name is no definition on its way (a typo, a component this deployment
	// does not run): a final rejection, which binds the change key (D77)
	ghost := grantReq("p0", root, sectest.Bob, []sdkauthz.Segment{{ResourceType: "demo.ghost", Operation: "demo.ghost.read", Atoms: map[string]sdkauthz.Atom{},
		ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}}})
	refused := submitChange(t, w, sectest.Alice, ghost, 400)
	assert.Equal(t, "REQUEST_INVALID", refused["reason"])
	assert.Contains(t, refused["detail"], "not registered")
	ghostAgain := submitChange(t, w, sectest.Alice, ghost, 400)
	assert.Equal(t, refused["detail"], ghostAgain["detail"], "the key is bound: the same answer")

	pending := submitChange(t, w, sectest.Alice, invoiceGrant, 503)
	assert.Equal(t, "DEFINITION_PENDING", pending["reason"])
	submitChange(t, w, sectest.Alice, invoiceGrant, 503) // not bound: checked again
	require.NoError(t, invoices.Validate())
	require.NoError(t, invoices.Submit(ctx, authzv3.NewDefinitionServiceClient(dial(t, w, "demo/invoices")), w.Deployment, "3.0.0"))
	submitChange(t, w, sectest.Alice, invoiceGrant, 200)
	east := protect(t, w, sectest.Alice, unitReq("u1", root, "east", []sdkauthz.Segment{orderSeg(region("east"))}, []string{"demo.order.read"}))
	eastID := east["record"].(string)
	protect(t, w, sectest.Alice, holdingReq("h1", eastID, sectest.Bob))
	authzSegs := []sdkauthz.Segment{}
	for _, op := range []string{OpRead, OpChange, OpTighten} { // a manager: changes and tightenings (A125)
		authzSegs = append(authzSegs, sdkauthz.Segment{ResourceType: Records, Operation: op, Atoms: map[string]sdkauthz.Atom{Holder: {Kind: "all"}},
			ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}})
	}
	submitChange(t, w, sectest.Alice, grantReq("g0", root, sectest.Bob, authzSegs), 200)

	// Bob grants within his limit; beyond it is refused (the boundary card's story)
	waitForView(t, w, sectest.Bob) // his grant on the member's own records reaches the member's own view
	ok := submitChange(t, w, sectest.Bob, grantReq("b1", eastID, carol, []sdkauthz.Segment{orderSeg(region("east"))}), 200)
	beyond := submitChange(t, w, sectest.Bob, grantReq("b2", eastID, carol, []sdkauthz.Segment{orderSeg(region("east", "west"))}), 403)
	assert.Equal(t, "CONTAINMENT_NOT_PROVEN", beyond["reason"])
	again := submitChange(t, w, sectest.Bob, grantReq("b2", eastID, carol, []sdkauthz.Segment{orderSeg(region("east", "west"))}), 403)
	assert.Equal(t, "CONTAINMENT_NOT_PROVEN", again["reason"], "a final rejection binds its key")
	conflict := submitChange(t, w, sectest.Bob, grantReq("b1", eastID, carol, []sdkauthz.Segment{orderSeg(region("west"))}), 409)
	assert.Equal(t, "CHANGE_KEY_CONFLICT", conflict["reason"])
	replay := submitChange(t, w, sectest.Bob, grantReq("b1", eastID, carol, []sdkauthz.Segment{orderSeg(region("east"))}), 200)
	assert.Equal(t, ok["record"], replay["record"], "the same change under its key: the same result, no second record")
	outside := submitChange(t, w, sectest.Bob, grantReq("b3", root, carol, []sdkauthz.Segment{orderSeg(region("west"))}), 403)
	assert.Equal(t, "PERMISSION_DENIED", outside["reason"], "Bob does not manage the root")

	// the grant reaches demo/orders' view at its next verification; a revocation leaves it at the next one
	ans := verify(held)
	require.Equal(t, "changed", ans.Shards[0].Status)
	require.Contains(t, ans.Shards[0].View.Subjects, carol)
	held.Digest = ans.Shards[0].View.Digest
	submitChange(t, w, sectest.Alice, tightenReq("r1", ok["record"]), 200)
	ans = verify(held)
	require.Equal(t, "changed", ans.Shards[0].Status)
	assert.NotContains(t, ans.Shards[0].View.Subjects, carol, "revoked: gone from the very next view")

	// the last authorization admin stays
	holdings := listRecords(t, w, sectest.Alice, "management_holding")
	var aliceHolding string
	for _, h := range holdings {
		if b := h["body"].(map[string]any); b["holder"] == sectest.Alice {
			aliceHolding = h["id"].(string)
		}
	}
	last := submitChange(t, w, sectest.Alice, tightenReq("e1", aliceHolding), 409)
	assert.Equal(t, "LAST_ADMIN_PROTECTED", last["reason"])

	e.root, e.east = root, eastID
}

// lifecycle is T4's first part: narrowing, stale revisions, splitting, renewals, terminations, validity.
func (e *e2e) lifecycle() {
	t, w, admin, ctx, verify, held, root := e.t, e.w, e.admin, e.ctx, e.verify, e.held, e.root
	defer func() { e.held = held }()
	// T4: the lifecycle at the effect point (security 08): records read back from the table
	type row struct {
		State, EndReason   string
		Revision, StateRev int64
		Predecessor        string
	}
	recordRow := func(id any) row {
		var r row
		var end, pred *string
		require.NoError(t, admin.QueryRow(ctx, "SELECT state, end_reason, revision, state_revision, predecessor::text FROM "+
			itSchema+".authz_record WHERE id = $1", id).Scan(&r.State, &end, &r.Revision, &r.StateRev, &pred))
		if end != nil {
			r.EndReason = *end
		}
		if pred != nil {
			r.Predecessor = *pred
		}
		return r
	}
	wide := submitChange(t, w, sectest.Alice, grantReq("t1", root, carol, []sdkauthz.Segment{orderSeg(region("east", "west"))}), 200)
	assert.Equal(t, "applied", wide["outcome"])
	assert.Equal(t, map[string]any{"domain": "authz.record.state", "value": "1"}, wide["new_revision"])
	// a narrowing: the same record, a new content revision
	narrow := map[string]any{"change_key": "t2", "direction": "tighten", "target": wide["record"],
		"expected_state_revision": map[string]any{"domain": "authz.record.state", "value": "1"},
		"expected_revision":       map[string]any{"domain": "authz.record.revision", "value": "1"}}
	cand, _ := json.Marshal(map[string]any{"governance_unit": root, "grantee": carol, "segments": []sdkauthz.Segment{orderSeg(region("east"))}})
	narrow["candidate"], narrow["candidate_digest"] = json.RawMessage(cand), candidateDigest("grant", cand)
	n := submitChange(t, w, sectest.Alice, narrow, 200)
	assert.Equal(t, wide["record"], n["record"], "a narrowing keeps the record")
	assert.Equal(t, row{State: "active", Revision: 2, StateRev: 2}, recordRow(wide["record"]))
	// the same request again: its stale revisions (CHANGE_REVISION_STALE, rows 4 and 17) never reach it, the key does
	again2 := narrow
	again2["change_key"], again2["expected_revision"] = "t3", map[string]any{"domain": "authz.record.revision", "value": "2"}
	stale := submitChange(t, w, sectest.Alice, again2, 409)
	assert.Equal(t, "CHANGE_REVISION_STALE", stale["reason"], "the state revision moved on (row 4)")
	again2["change_key"], again2["expected_state_revision"] = "t4", map[string]any{"domain": "authz.record.state", "value": "2"}
	again2["expected_revision"] = map[string]any{"domain": "authz.record.revision", "value": "1"}
	stale = submitChange(t, w, sectest.Alice, again2, 409)
	assert.Equal(t, "CHANGE_REVISION_STALE", stale["reason"], "the content revision moved on (row 17)")
	// a tightening whose candidate is wider: split it
	wider := map[string]any{"change_key": "t5", "direction": "tighten", "target": wide["record"]}
	cand, _ = json.Marshal(map[string]any{"governance_unit": root, "grantee": carol, "segments": []sdkauthz.Segment{orderSeg(region("east", "north"))}})
	wider["candidate"], wider["candidate_digest"] = json.RawMessage(cand), candidateDigest("grant", cand)
	split := submitChange(t, w, sectest.Alice, wider, 400)
	assert.Contains(t, split["detail"], "split into a tightening and a widening")
	// a renewal that does not contain its predecessor: rejected for good, the candidate kept as ended (rejected)
	renew := grantReq("t6", root, carol, []sdkauthz.Segment{orderSeg(region("north"))})
	cand, _ = json.Marshal(map[string]any{"governance_unit": root, "grantee": carol, "segments": []sdkauthz.Segment{orderSeg(region("north"))},
		"predecessor": wide["record"], "record_type": "grant"})
	renew["candidate"], renew["candidate_digest"] = json.RawMessage(cand), candidateDigest("grant", cand)
	notContained := submitChange(t, w, sectest.Alice, renew, 403)
	assert.Equal(t, "CONTAINMENT_NOT_PROVEN", notContained["reason"])
	code, byKey := call(t, w, sectest.Alice, "GET", "/api/authz/changes/t6", nil)
	require.Equal(t, 200, code)
	assert.Equal(t, "rejected", byKey["outcome"], "a final rejection binds the key")
	assert.Equal(t, row{State: "ended", EndReason: "rejected", Revision: 1, StateRev: 1, Predecessor: wide["record"].(string)},
		recordRow(byKey["record"]))
	// one that does: the predecessor ends superseded in the same transaction
	cand, _ = json.Marshal(map[string]any{"governance_unit": root, "grantee": carol, "segments": []sdkauthz.Segment{orderSeg(region("east", "north"))},
		"predecessor": wide["record"], "record_type": "grant"})
	renew = map[string]any{"change_key": "t7", "direction": "widen", "candidate": json.RawMessage(cand), "candidate_digest": candidateDigest("grant", cand)}
	renewed := submitChange(t, w, sectest.Alice, renew, 200)
	assert.Equal(t, row{State: "ended", EndReason: "superseded", Revision: 2, StateRev: 3}, recordRow(wide["record"]))
	assert.Equal(t, wide["record"], recordRow(renewed["record"]).Predecessor)
	code, out := call(t, w, sectest.Alice, "GET", "/api/authz/changes/never-used", nil)
	require.Equal(t, 200, code)
	assert.Equal(t, "unbound", out["outcome"], "nothing bound under the key: submit it again with the same key")
	ended := submitChange(t, w, sectest.Alice, tightenReq("t8", renewed["record"]), 200)
	assert.Equal(t, row{State: "ended", EndReason: "revoked", Revision: 1, StateRev: 2, Predecessor: wide["record"].(string)},
		recordRow(ended["record"]), "a manager's revocation")
	// a termination of an effective record is stale (row 4)
	live := submitChange(t, w, sectest.Alice, grantReq("t9a", root, carol, []sdkauthz.Segment{orderSeg(region("east"))}), 200)
	term := map[string]any{"change_key": "t9", "direction": "tighten", "target": live["record"], "termination": "cancel",
		"expected_state_revision": map[string]any{"domain": "authz.record.state", "value": "1"}}
	assert.Equal(t, "CHANGE_REVISION_STALE", submitChange(t, w, sectest.Alice, term, 409)["reason"])
	submitChange(t, w, sectest.Alice, tightenReq("t9b", live["record"]), 200)
	// a record past its own validity gives no access at once, before anything ends it
	cand, _ = json.Marshal(map[string]any{"record_type": "grant", "governance_unit": root, "grantee": carol,
		"segments": []sdkauthz.Segment{orderSeg(region("east"))},
		"valid":    map[string]any{"from": "2026-01-01T00:00:00.000000Z", "until": "2026-01-02T00:00:00.000000Z"}})
	past := submitChange(t, w, sectest.Alice, map[string]any{"change_key": "t11", "direction": "widen",
		"candidate": json.RawMessage(cand), "candidate_digest": candidateDigest("grant", cand)}, 200)
	assert.Equal(t, "active", recordRow(past["record"]).State)
	ans := verify(held)
	if ans.Shards[0].Status == "changed" {
		held.Digest = ans.Shards[0].View.Digest
		assert.NotContains(t, ans.Shards[0].View.Subjects, carol, "past its validity: not in the view")
	} else {
		t.Fatalf("the view did not change after an applied change: %s", ans.Shards[0].Status)
	}
	e.subjects = ans.Shards[0].View.Subjects // the last view seen; "unchanged" answers carry none
}

// audited: every applied change was audited in its transaction.
func (e *e2e) audited() {
	t, admin, ctx := e.t, e.admin, e.ctx
	var audited int
	require.NoError(t, admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".be_audit_log WHERE category = 'security_change'").Scan(&audited))
	assert.GreaterOrEqual(t, audited, 6, "install claim, unit, holding, two grants, revocation")
}
