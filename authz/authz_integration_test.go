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
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/config"
	"github.com/brickKit/be-sdk-go/v3/launcher"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	itPort   = "28223"
	itBase   = "http://localhost:" + itPort
	itSystem = "localhost:9223"
	itSchema = "authz_it"
	itDB     = "brickkit_test_db"
	carol    = "0190f3a1-0000-7000-8000-0000000000c3"
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
	"permission\tinfra.authz.system.read\tinfra/authz\npermission\tinfra.authz.system.verify\tinfra/authz\n" +
	"permission\tinfra.authz.system.submit\tinfra/authz\n" +
	"resource_type\tdemo.order\tdemo/orders\npermission\tdemo.order.read\tdemo/orders\n"

func region(v ...string) map[string]sdkauthz.Atom {
	return map[string]sdkauthz.Atom{"region": {Kind: "in", Values: v}}
}

func orderSeg(atoms map[string]sdkauthz.Atom) sdkauthz.Segment {
	return sdkauthz.Segment{ResourceType: "demo.order", Operation: "demo.order.read", Atoms: atoms,
		ReadFields: []string{"id", "total"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}}
}

func TestMemberEndToEnd(t *testing.T) {
	pgPassword := os.Getenv("AUTHZ_IT_PG_PASSWORD")
	if pgPassword == "" {
		t.Fatal("AUTHZ_IT_PG_PASSWORD is not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, "postgres://postgres:"+url.QueryEscape(pgPassword)+"@localhost:5432/"+itDB+"?sslmode=disable")
	require.NoError(t, err)
	defer admin.Close(ctx)
	_, err = admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+itSchema+" CASCADE; CREATE SCHEMA "+itSchema)
	require.NoError(t, err)

	w := sectest.New(t)
	portFree(t, itPort, itSystem)
	env := w.Env(t, ID)
	for k, v := range map[string]string{"COMPONENT_ID": ID, "COMPONENT_VERSION": Version, "PORT": itPort, "STOP_DRAIN_DELAY": "50ms",
		"PG_HOST": "localhost", "PG_DATABASE": itDB, "PG_USER": "postgres", "PG_PASSWORD": pgPassword, "PG_SCHEMA": itSchema,
		"PG_OWNER_USER": "postgres", "PG_OWNER_PASSWORD": pgPassword, "AUTHZ_INSTANCE": "authz-it-instance",
		"AUTHZ_REGISTRY": registryTSV, "AUTHZ_BOOTSTRAP_ADMIN": sectest.Alice,
		"AUTHZ_GRPC_URL": "http://" + itSystem} { // the member guards its own user surface with its own view
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

	src := sdkauthz.GRPCSource{Conn: conn}
	verify := func(held ...sdkauthz.Held) sdkauthz.VerifyAnswer {
		ans, err := src.Verify(ctx, sdkauthz.VerifyRequest{Component: "demo/orders", Nonce: "n1", Held: held})
		require.NoError(t, err, "the view opens: canonical, its digest, the schema")
		require.Len(t, ans.Shards, 1)
		return ans
	}
	ans := verify()
	assert.Equal(t, "changed", ans.Shards[0].Status)
	assert.Equal(t, "authz-it-instance", ans.Instance)
	assert.Equal(t, []string{"demo.order"}, ans.Shards[0].View.Applicability)
	held := sdkauthz.Held{Shard: ans.Shards[0].Shard, Digest: ans.Shards[0].View.Digest}
	assert.Equal(t, "unchanged", verify(held).Shards[0].Status)

	// the effect point: Alice (the install claim) sets up a unit limited to the east and lets Bob manage it
	units := listRecords(t, w, sectest.Alice, "management_unit")
	require.Len(t, units, 1)
	root := units[0]["id"].(string)
	east := submitChange(t, w, sectest.Alice, map[string]any{"change_key": "u1", "action": "unit.create", "unit": root, "name": "east",
		"managed_scope": []sdkauthz.Segment{orderSeg(region("east"))}, "grantable_operations": []string{"demo.order.read"}}, 200)
	eastID := east["record"].(string)
	submitChange(t, w, sectest.Alice, map[string]any{"change_key": "h1", "action": "holding.create", "unit": eastID, "holder": sectest.Bob}, 200)
	authzSegs := []sdkauthz.Segment{}
	for _, op := range []string{OpRead, OpChange} {
		authzSegs = append(authzSegs, sdkauthz.Segment{ResourceType: Records, Operation: op, Atoms: map[string]sdkauthz.Atom{},
			ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}})
	}
	submitChange(t, w, sectest.Alice, map[string]any{"change_key": "g0", "action": "grant.create", "unit": root, "grantee": sectest.Bob,
		"segments": authzSegs}, 200)

	// Bob grants within his limit; beyond it is refused (the boundary card's story)
	waitForView(t, w, sectest.Bob) // his grant on the member's own records reaches the member's own view
	ok := submitChange(t, w, sectest.Bob, map[string]any{"change_key": "b1", "action": "grant.create", "unit": eastID, "grantee": carol,
		"segments": []sdkauthz.Segment{orderSeg(region("east"))}}, 200)
	beyond := submitChange(t, w, sectest.Bob, map[string]any{"change_key": "b2", "action": "grant.create", "unit": eastID, "grantee": carol,
		"segments": []sdkauthz.Segment{orderSeg(region("east", "west"))}}, 403)
	assert.Equal(t, "CONTAINMENT_NOT_PROVEN", beyond["reason"])
	again := submitChange(t, w, sectest.Bob, map[string]any{"change_key": "b2", "action": "grant.create", "unit": eastID, "grantee": carol,
		"segments": []sdkauthz.Segment{orderSeg(region("east", "west"))}}, 403)
	assert.Equal(t, "CONTAINMENT_NOT_PROVEN", again["reason"], "a final rejection binds its key")
	conflict := submitChange(t, w, sectest.Bob, map[string]any{"change_key": "b1", "action": "grant.create", "unit": eastID, "grantee": carol,
		"segments": []sdkauthz.Segment{orderSeg(region("west"))}}, 409)
	assert.Equal(t, "CHANGE_KEY_CONFLICT", conflict["reason"])
	replay := submitChange(t, w, sectest.Bob, map[string]any{"change_key": "b1", "action": "grant.create", "unit": eastID, "grantee": carol,
		"segments": []sdkauthz.Segment{orderSeg(region("east"))}}, 200)
	assert.Equal(t, ok["record"], replay["record"], "the same change under its key: the same result, no second record")
	outside := submitChange(t, w, sectest.Bob, map[string]any{"change_key": "b3", "action": "grant.create", "unit": root, "grantee": carol,
		"segments": []sdkauthz.Segment{orderSeg(region("west"))}}, 403)
	assert.Equal(t, "PERMISSION_DENIED", outside["reason"], "Bob does not manage the root")

	// the grant reaches demo/orders' view at its next verification; a revocation leaves it at the next one
	ans = verify(held)
	require.Equal(t, "changed", ans.Shards[0].Status)
	require.Contains(t, ans.Shards[0].View.Subjects, carol)
	held.Digest = ans.Shards[0].View.Digest
	submitChange(t, w, sectest.Alice, map[string]any{"change_key": "r1", "action": "grant.revoke", "target": ok["record"]}, 200)
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
	last := submitChange(t, w, sectest.Alice, map[string]any{"change_key": "e1", "action": "holding.end", "target": aliceHolding}, 409)
	assert.Equal(t, "LAST_ADMIN_PROTECTED", last["reason"])

	// every applied change was audited in its transaction
	var audited int
	require.NoError(t, admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".be_audit_log WHERE category = 'security_change'").Scan(&audited))
	assert.GreaterOrEqual(t, audited, 6, "install claim, unit, holding, two grants, revocation")
}

func dial(t *testing.T, w *sectest.World, component string) *grpc.ClientConn {
	tls := w.TLS(t, component)
	conn, err := grpc.NewClient(itSystem, grpc.WithTransportCredentials(credentials.NewTLS(tls.ClientConfig(ID))))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

func call(t *testing.T, w *sectest.World, who, method, path string, body any) (int, map[string]any) {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, itBase+path, r)
	req.Header.Set("Authorization", w.Bearer(who))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]any{"raw": string(b)}
	}
	return resp.StatusCode, out
}

func submitChange(t *testing.T, w *sectest.World, who string, body map[string]any, want int) map[string]any {
	t.Helper()
	code, out := call(t, w, who, "POST", "/api/authz/changes", body)
	require.Equal(t, want, code, "%v: %v", body["change_key"], out)
	return out
}

func listRecords(t *testing.T, w *sectest.World, who, typ string) []map[string]any {
	t.Helper()
	code, out := call(t, w, who, "GET", "/api/authz/records?type="+typ, nil)
	require.Equal(t, 200, code, "%v", out)
	var list []map[string]any
	for _, r := range out["records"].([]any) {
		list = append(list, r.(map[string]any))
	}
	return list
}

// waitForView waits until a principal's new grant on the member's own records is in the member's own view (it
// verifies every 2.5 s).
func waitForView(t *testing.T, w *sectest.World, who string) {
	require.Eventually(t, func() bool {
		code, _ := call(t, w, who, "GET", "/api/authz/records?type=grant", nil)
		return code == 200
	}, 10*time.Second, 200*time.Millisecond)
}

// portFree fails at once when a port the member needs is taken: a running cell (host ports 18xxx) or another member
// would answer in its place, and the test would assert against another process.
func portFree(t *testing.T, addrs ...string) {
	for _, a := range addrs {
		if !strings.Contains(a, ":") {
			a = "localhost:" + a
		}
		ln, err := net.Listen("tcp", a)
		require.NoError(t, err, "port %s is taken: is a cell or another member running?", a)
		_ = ln.Close()
	}
}
