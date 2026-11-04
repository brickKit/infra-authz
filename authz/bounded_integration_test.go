//go:build integration

package authz

import (
	"encoding/json"
	"fmt"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The people of the bounded phase: a manager of two units and an own-records unit, two grantees, and one whose
// grants fill the budget.
const (
	mia    = "0190f3a1-0000-7000-8000-0000000000a1"
	xavier = "0190f3a1-0000-7000-8000-0000000000a2"
	yara   = "0190f3a1-0000-7000-8000-0000000000a3"
	filler = "0190f3a1-0000-7000-8000-0000000000a4"
)

// ledger is a component whose resource has a dimension of each kind the containment rules compare: a party
// (principal), an amount, a department (org tree).
var ledger = &sdkauthz.Definitions{Component: "demo/ledger",
	Resources: []sdkauthz.Resource{{Type: "demo.entry", ViewOperation: "demo.entry.read",
		Dimensions: map[string]sdkauthz.Dimension{
			"owner":  {Kind: sdkauthz.Principal, Column: "owner", PrincipalRole: "owner"},
			"amount": {Kind: sdkauthz.Amount, Column: "amount", CurrencyColumn: "currency"},
			"dept":   {Kind: sdkauthz.OrgTree, Column: "dept"}},
		Fields: map[string]sdkauthz.Field{"id": {Class: sdkauthz.Ordinary}, "total": {Class: sdkauthz.Ordinary},
			"note": {Class: sdkauthz.Ordinary}}}},
	Operations: []sdkauthz.Operation{{Key: "demo.entry.read", ResourceType: "demo.entry", Purpose: "read", RiskClass: "low"}}}

func entrySeg(owner, amount, dept sdkauthz.Atom, fields ...string) sdkauthz.Segment {
	if fields == nil {
		fields = []string{"id"}
	}
	return sdkauthz.Segment{ResourceType: "demo.entry", Operation: "demo.entry.read",
		Atoms: map[string]sdkauthz.Atom{"owner": owner, "amount": amount, "dept": dept}, ReadFields: fields,
		Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}}
}

func amountUpTo(lo, hi string) sdkauthz.Atom {
	yes := true
	return sdkauthz.Atom{Kind: "interval", Currency: "CNY", Lo: &lo, LoClosed: &yes, Hi: &hi, HiClosed: &yes}
}

func depts(paths ...string) sdkauthz.Atom {
	a := sdkauthz.Atom{Kind: "tree"}
	for _, p := range paths {
		a.Items = append(a.Items, sdkauthz.TreeItem{Path: p, Mode: "subtree"})
	}
	return a
}

var (
	anyone = sdkauthz.Atom{Kind: "all"}
	self   = sdkauthz.Atom{Kind: "self"}
)

func people(p ...string) sdkauthz.Atom { return sdkauthz.Atom{Kind: "in", Values: p} }

// bounded is T7a (security 04's containment, security 07's subject-relative atoms and budgets): a manager of two
// units grants within each, never across them nor with one's amount and the other's departments (AM02); a wider
// field, validity or an expression the rules do not compare is refused, never passed by dropping it (AM03); self is
// the candidate grantee, on both sides (AM04); a grant over a budget is refused, a restore over one stays held
// (FX04, rows 19 and 26). It runs after the releases phase: Judy, an available admin, confirms.
func (e *e2e) bounded() {
	t, w, ctx, root := e.t, e.w, e.ctx, e.root
	require.NoError(t, ledger.Validate())
	require.NoError(t, ledger.Submit(ctx, authzv3.NewDefinitionServiceClient(dial(t, w, "demo/ledger")), w.Deployment, "3.0.0"))
	for _, p := range []string{mia, xavier, yara, filler} {
		require.NoError(t, e.iam.set(ctx, p, "active", 1))
	}
	ops := []string{"demo.entry.read"}
	unit := func(key, parent, name string, scope ...sdkauthz.Segment) string {
		return protectBy(t, w, sectest.Alice, judy, unitReq(key, parent, name, scope, ops))["record"].(string)
	}
	scoped := func(s sdkauthz.Segment, until string) sdkauthz.Segment { s.Valid.Until = until; return s }
	a1 := unit("bd-a1", root, "bd-a1", scoped(entrySeg(anyone, amountUpTo("0", "100"), depts("le1/a"), "id", "total"), "2030-01-01T00:00:00.000000Z"))
	b2 := unit("bd-b2", root, "bd-b2", entrySeg(anyone, amountUpTo("0", "50"), depts("le1/b")))
	named := unit("bd-named", root, "bd-named", entrySeg(people(xavier), anyone, anyone))
	selves := unit("bd-selves", root, "bd-selves", entrySeg(self, anyone, anyone))
	mgrSegs := []sdkauthz.Segment{}
	for _, op := range []string{OpRead, OpChange} {
		mgrSegs = append(mgrSegs, sdkauthz.Segment{ResourceType: Records, Operation: op, Atoms: map[string]sdkauthz.Atom{Holder: {Kind: "all"}},
			ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}})
	}
	submitChange(t, w, sectest.Alice, grantReq("bd-mg", root, mia, mgrSegs), 200)
	for _, u := range []string{a1, b2, named, selves} {
		protectBy(t, w, sectest.Alice, judy, holdingReq("bd-h-"+u, u, mia))
	}
	waitForView(t, w, mia)
	refused := func(key, u, grantee string, s ...sdkauthz.Segment) string {
		t.Helper()
		out := submitChange(t, w, mia, grantReq(key, u, grantee, s), 403)
		require.Equal(t, "CONTAINMENT_NOT_PROVEN", out["reason"], "%v", out)
		return out["detail"].(string)
	}

	// AM02: each pairing within its own unit; across them, or one unit's amount with the other's departments, refused
	submitChange(t, w, mia, grantReq("bd1", a1, xavier, []sdkauthz.Segment{scoped(entrySeg(anyone, amountUpTo("0", "100"), depts("le1/a")), "2029-01-01T00:00:00.000000Z")}), 200)
	submitChange(t, w, mia, grantReq("bd2", b2, xavier, []sdkauthz.Segment{entrySeg(anyone, amountUpTo("0", "50"), depts("le1/b/c"))}), 200)
	assert.Contains(t, refused("bd3", b2, xavier, entrySeg(anyone, amountUpTo("0", "50"), depts("le1/a"))), "dept", "a1's departments in b2")
	assert.Contains(t, refused("bd4", b2, xavier, entrySeg(anyone, amountUpTo("0", "100"), depts("le1/b"))), "amount", "a1's amount borrowed in b2")
	assert.Contains(t, refused("bd5", a1, xavier, scoped(entrySeg(anyone, amountUpTo("0", "100"), depts("le1/a", "le1/b")), "2029-01-01T00:00:00.000000Z")),
		"dept", "both units' departments in one segment")

	// AM03: a wider field, a longer validity, an expression outside the rules (a named set on a tree): refused, saying where
	in1 := func(s sdkauthz.Segment) sdkauthz.Segment { return scoped(s, "2029-01-01T00:00:00.000000Z") }
	assert.Contains(t, refused("bd6", a1, xavier, in1(entrySeg(anyone, amountUpTo("0", "100"), depts("le1/a"), "id", "note"))), "read_fields")
	assert.Contains(t, refused("bd7", a1, xavier, entrySeg(anyone, amountUpTo("0", "100"), depts("le1/a"))), "valid", "no end: beyond 2030")
	assert.Contains(t, refused("bd8", a1, xavier, in1(entrySeg(anyone, amountUpTo("0", "100"), people("le1/a")))), "unprovable")

	// AM04: self is the candidate grantee: within {xavier} for Xavier, not for Yara, though the words are the same;
	// a limit's self is the grantee too
	submitChange(t, w, mia, grantReq("bd9", named, xavier, []sdkauthz.Segment{entrySeg(self, anyone, anyone)}), 200)
	refused("bd10", named, yara, entrySeg(self, anyone, anyone))
	submitChange(t, w, mia, grantReq("bd11", selves, xavier, []sdkauthz.Segment{entrySeg(people(xavier), amountUpTo("0", "10"), anyone)}), 200)
	refused("bd12", selves, xavier, entrySeg(people(xavier, yara), anyone, anyone))
	submitChange(t, w, mia, grantReq("bd12y", selves, yara, []sdkauthz.Segment{entrySeg(self, anyone, anyone)}), 200)
	ledgerView := sdkauthz.GRPCSource{Conn: dial(t, w, "demo/ledger")}
	require.Eventually(t, func() bool {
		ans, err := ledgerView.Verify(ctx, sdkauthz.VerifyRequest{Component: "demo/ledger", Nonce: "n1"})
		if err != nil || len(ans.Shards) != 1 || ans.Shards[0].View == nil {
			return false
		}
		selves := 0
		for _, s := range ans.Shards[0].View.Subjects[xavier].Segments {
			if s.Atoms["owner"].Kind == "self" {
				selves++
			}
		}
		return selves == 2
	}, 10*time.Second, 200*time.Millisecond, "Xavier's grants under the named and the self units: self, him")
	// a disposition's scope is the disposed person's: self within the named unit's {xavier} is him
	code, dout := call(t, w, sectest.Alice, "POST", "/api/authz/dispositions", map[string]any{"change_key": "bd-d1", "subject": xavier,
		"domain": named, "suspended_segments": []sdkauthz.Segment{entrySeg(self, anyone, anyone)}})
	require.Equal(t, 200, code, "%v", dout)
	// a unit's scope within its parent's has no grantee yet: self within self; self within a named set, or a named
	// set within self, cannot be proven
	protectBy(t, w, sectest.Alice, judy, subUnitReq("bd13", selves, "bd-selves-sub", []sdkauthz.Segment{entrySeg(self, anyone, anyone)}, ops))
	for key, c := range map[string][2]any{"bd14": {named, self}, "bd15": {selves, people(xavier)}} {
		out := submitChange(t, w, sectest.Alice, unitReq(key, c[0], key, []sdkauthz.Segment{entrySeg(c[1].(sdkauthz.Atom), anyone, anyone)}, ops), 403)
		assert.Contains(t, out["detail"], "unprovable", "%s: %v", key, out)
	}

	e.budgets(root)
}

// budgets is FX04: one grant's segments, values and tree items, and one person's segments on one operation, each
// over its budget, refused (row 19); a renewal does not count the record it supersedes; a restore over the budget
// stays held (row 26).
func (e *e2e) budgets(root string) {
	t, w, admin, ctx := e.t, e.w, e.admin, e.ctx
	over := func(key string, s ...sdkauthz.Segment) string {
		t.Helper()
		out := submitChange(t, w, sectest.Alice, grantReq(key, root, filler, s), 403)
		require.Equal(t, "CONTAINMENT_NOT_PROVEN", out["reason"], "%v", out)
		assert.Contains(t, out["detail"], "row 19: over budget", "%v", out)
		return out["detail"].(string)
	}
	n := 0
	next := func(k int) []sdkauthz.Segment { // k segments, each a scope of its own
		var out []sdkauthz.Segment
		for i := 0; i < k; i++ {
			out = append(out, entrySeg(anyone, amountUpTo(fmt.Sprint(n), "1000"), anyone))
			n++
		}
		return out
	}
	assert.Contains(t, over("bb1", next(budgetGrantSegments+1)...), "segments in one grant")
	values := make([]string, budgetInValues+1)
	for i := range values {
		values[i] = fmt.Sprintf("p%04d", i)
	}
	assert.Contains(t, over("bb2", entrySeg(people(values...), anyone, anyone)), "values on owner")
	var items []string
	for i := 0; i <= budgetTreeItems; i++ {
		items = append(items, fmt.Sprintf("le1/d%02d", i))
	}
	assert.Contains(t, over("bb3", entrySeg(anyone, anyone, depts(items...))), "tree items on dept")

	// a grant held uncomputable does not count: written with an atom the table cannot meet (as the uncomputable
	// phase does), its unit narrowed so the closure finds it
	u := protectBy(t, w, sectest.Alice, judy, unitReq("bb-u", root, "bb-u", []sdkauthz.Segment{entrySeg(people(filler), anyone, anyone)},
		[]string{"demo.entry.read"}))["record"]
	narrow := func(key, dept string) {
		raw, _ := json.Marshal(unitDefaults(map[string]any{"name": "bb-u", "parent": root, "managed_scope": []sdkauthz.Segment{entrySeg(people(filler), anyone, depts(dept))},
			"grantable_operations": []string{"demo.entry.read"}}))
		submitChange(t, w, sectest.Alice, map[string]any{"change_key": key, "direction": "tighten", "target": u,
			"candidate": json.RawMessage(raw), "candidate_digest": candidateDigest("management_unit", raw)}, 200)
	}
	setOwner := func(id any, atom string) {
		_, err := admin.Exec(ctx, "UPDATE "+itSchema+".authz_record SET body = jsonb_set(body, '{segments,0,atoms,owner}', $2::jsonb) WHERE id = $1", id, atom)
		require.NoError(t, err)
	}
	g := submitChange(t, w, sectest.Alice, grantReq("bb-g", u, filler, []sdkauthz.Segment{entrySeg(self, anyone, depts("le1/z"))}), 200)["record"]
	setOwner(g, `{"kind":"tree","items":[{"path":"/x","mode":"subtree"}]}`)
	narrow("bb-n1", "le1")
	require.Eventually(t, func() bool { return recordOf(t, admin, g).State == "held" }, 10*time.Second, 100*time.Millisecond, "held, uncomputable")

	// a grant a disposition holds does not count either: released over the budget, it is kept held (restore_pending)
	d := submitChange(t, w, sectest.Alice, grantReq("bb-d", root, filler, []sdkauthz.Segment{entrySeg(anyone, anyone, depts("le2/held"))}), 200)["record"]
	code, out := call(t, w, sectest.Alice, "POST", "/api/authz/dispositions", map[string]any{"change_key": "bb-d1", "subject": filler,
		"suspended_segments": []sdkauthz.Segment{entrySeg(anyone, anyone, depts("le2/held"))}})
	require.Equal(t, 200, code, "%v", out)
	disposition := out["record"]
	require.Equal(t, "held", recordOf(t, admin, d).State)

	// the budget of one person on one operation: 64 scopes fill it (one grant waiting to take effect counts too), one
	// more is refused; a renewal gives way: the first grant's segments end in 2030, its renewal's do not
	var first any
	for i := 0; i < budgetSubjectSegments/budgetGrantSegments; i++ {
		segs := next(budgetGrantSegments)
		if i == 0 {
			for j := range segs {
				segs[j].Valid.Until = "2030-01-01T00:00:00.000000Z"
			}
		}
		req, want := grantReq(fmt.Sprintf("bb-f%d", i), root, filler, segs), 200
		if i == 1 {
			req, want = scheduledGrant(fmt.Sprintf("bb-f%d", i), root, filler, segs, time.Hour), 202
		}
		out := submitChange(t, w, sectest.Alice, req, want)
		if i == 0 {
			first = out["record"]
		}
	}
	assert.Contains(t, over("bb4", next(1)...), "more than 64 segments")
	var segs []sdkauthz.Segment
	require.NoError(t, admin.QueryRow(ctx, "SELECT body->'segments' FROM "+itSchema+".authz_record WHERE id = $1", first).Scan(&segs))
	for j := range segs {
		segs[j].Valid.Until = "" // longer: other scopes than its predecessor's, which give way
	}
	submitChange(t, w, sectest.Alice, widenReq("bb5", "grant", map[string]any{"governance_unit": root, "grantee": filler,
		"predecessor": first, "segments": segs}), 200)
	code, out = call(t, w, sectest.Alice, "POST", "/api/authz/dispositions/"+disposition.(string)+"/release", map[string]any{
		"change_key": "bb-d2", "disposition_revision": map[string]any{"domain": dispositionDomain, "value": "1"}})
	require.Equal(t, 200, code, "%v", out)
	var hold string
	require.NoError(t, admin.QueryRow(ctx, "SELECT state || ':' || coalesce(hold_reason, '') FROM "+itSchema+
		".authz_record WHERE id = $1", d).Scan(&hold))
	assert.Equal(t, "held:restore_pending", hold, "it would be the 65th")

	// repaired and its unit narrowed again: computable, but it would be the 65th: it stays held (row 26), saying why
	heldAt := recordOf(t, admin, g).StateRev
	setOwner(g, `{"kind":"self"}`)
	narrow("bb-n2", "le1/z")
	require.Eventually(t, func() bool {
		var st string
		return admin.QueryRow(ctx, "SELECT state FROM "+itSchema+".be_work_item WHERE job = $1 AND args->>'record' = $2"+
			" AND args->>'trigger' = $3 AND (args->>'state_revision')::bigint = $4", JobDue, g, triggerRestore, heldAt).Scan(&st) == nil &&
			st == "done"
	}, 10*time.Second, 100*time.Millisecond, "the restore entered the effect point (a kept hold does not bind its key)")
	assert.Equal(t, "held", recordOf(t, admin, g).State)
}
