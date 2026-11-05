//go:build integration

package authz

import (
	"encoding/json"
	"fmt"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// itPlanConfirmAbove is the test deployment's AUTHZ_PLAN_CONFIRM_ABOVE: a plan of more items is confirmed by a second
// person.
const itPlanConfirmAbove = 3

// planTest calls the plan routes as Alice.
type planTest struct{ e *e2e }

func (pt planTest) seg(r ...string) []sdkauthz.Segment {
	return []sdkauthz.Segment{orderSeg(region(r...))}
}

func (pt planTest) grant(key, who string, r ...string) any {
	return submitChange(pt.e.t, pt.e.w, sectest.Alice, grantReq(key, pt.e.root, who, pt.seg(r...)), 200)["record"]
}

func (pt planTest) plan(path string, body any, want int) map[string]any {
	pt.e.t.Helper()
	code, out := call(pt.e.t, pt.e.w, sectest.Alice, "POST", "/api/authz/plans"+path, body)
	require.Equal(pt.e.t, want, code, "%s: %v", path, out)
	return out
}

func (pt planTest) items(p map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, x := range p["items"].([]any) {
		it := x.(map[string]any)
		out[it["item_key"].(string)] = it
	}
	return out
}

func (pt planTest) get(id any) map[string]any {
	code, out := call(pt.e.t, pt.e.w, sectest.Alice, "GET", "/api/authz/plans/"+id.(string), nil)
	require.Equal(pt.e.t, 200, code, "%v", out)
	return out
}

func (pt planTest) until(id any, what string, ok func(map[string]any) bool) map[string]any {
	pt.e.t.Helper()
	var p map[string]any
	require.Eventually(pt.e.t, func() bool { p = pt.get(id); return ok(p) }, 15*time.Second, 200*time.Millisecond, "%s: %v", what, p)
	return p
}

func (pt planTest) states(p map[string]any) map[string]string {
	out := map[string]string{}
	for k, it := range pt.items(p) {
		out[k] = it["item_state"].(string)
	}
	return out
}

// confirm is Judy's confirmation of a plan, bound to digest.
func (pt planTest) confirm(id any, digest string) string {
	code, out := call(pt.e.t, pt.e.w, judy, "POST", "/api/authz/confirmations", map[string]any{"plan": id, "plan_digest": digest})
	require.Equal(pt.e.t, 201, code, "%v", out)
	return out["id"].(string)
}

// item is one plan item: a change request without its key.
func item(key string, req map[string]any) map[string]any {
	delete(req, "change_key")
	return map[string]any{"item_key": key, "request": req}
}

// plans is T7d (security 08's batch plans, A132): every item of a plan ends with a state of its own, never one
// success for the batch (CP21): applied, rejected, or to be reviewed when its target moved since the preview (CP03,
// CP105) or it saved a record awaiting confirmation, which then decides it (CP109); a plan above the threshold is
// confirmed by a second person, and an item stands on that person's eligibility when it runs (CP76); a reviewed item
// runs again under a new key; a cancelled or expired plan ends what has not run, applied items stay (CP34); a preview
// over the comparison budget is refused. It runs after the handover phase; Judy is the second confirmer.
func (e *e2e) plans() {
	t, w, admin, ctx, root := e.t, e.w, e.admin, e.ctx, e.root
	child := unitNamed(t, admin, "dl-child")
	pt := planTest{e}
	seg, grant, plan, items, get, until, states, confirmPlan := pt.seg, pt.grant, pt.plan, pt.items, pt.get, pt.until, pt.states, pt.confirm
	_ = get

	// a plan of five: two that apply, one beyond its unit, one whose target is revoked after the preview, one protected
	x, y, z := grant("pl-x", carol, "east"), grant("pl-y", carol, "west"), grant("pl-z", carol, "north")
	five := []any{
		item("a", grantReq("", root, pia, seg("south"))),
		item("b", tightenReq("", x)),
		item("c", grantReq("", child, carol, seg("south"))),
		item("d", tightenReq("", y)),
		item("e", unitReq("", root, "pl-unit", seg("east"), []string{"demo.order.read"})),
	}
	p := plan("", map[string]any{"plan_key": "pl1", "items": five}, 201)
	id := p["id"]
	assert.Equal(t, "draft", p["plan_state"])
	assert.Equal(t, id, plan("", map[string]any{"plan_key": "pl1", "items": five}, 201)["id"], "the same plan again")
	plan("", map[string]any{"plan_key": "pl1", "items": five[:2]}, 409)
	plan("", map[string]any{"plan_key": "pl0", "items": []any{map[string]any{"item_key": "k",
		"request": grantReq("own-key", root, pia, seg("south"))}}}, 400) // an item's key is the plan's to derive
	plan("/"+id.(string)+"/confirm", map[string]any{"preview_digest": "x"}, 409) // a draft is not confirmed
	p = plan("/"+id.(string)+"/preview", nil, 200)
	assert.Equal(t, "previewed", p["plan_state"])
	digest := p["preview_digest"].(string)
	assert.NotZero(t, p["comparisons"])
	assert.NotNil(t, items(p)["b"]["request"].(map[string]any)["expected_state_revision"], "the target's revisions recorded")
	submitChange(t, w, sectest.Alice, tightenReq("pl-y-off", y), 200) // after the preview: d's target moved
	plan("/"+id.(string)+"/confirm", map[string]any{"preview_digest": "x"}, 409)
	code, own := call(t, w, sectest.Alice, "POST", "/api/authz/confirmations", map[string]any{"plan": id, "plan_digest": digest})
	require.Equal(t, 403, code, "the initiator is not the second person: %v", own)
	held := plan("/"+id.(string)+"/confirm", map[string]any{"preview_digest": digest}, 202)
	assert.Equal(t, "CONFIRMATION_REQUIRED", held["reason"], "five items: a second person confirms")
	assert.Equal(t, "previewed", get(id)["plan_state"])
	plan("/"+id.(string)+"/confirm", map[string]any{"preview_digest": digest, "confirmation_ids": []string{confirmPlan(id, digest)}}, 200)
	p = until(id, "every item has run", func(p map[string]any) bool {
		s := states(p)
		return s["a"] != itemPending && s["b"] != itemPending && s["c"] != itemPending && s["d"] != itemPending && s["e"] != itemPending
	})
	assert.Equal(t, map[string]string{"a": itemApplied, "b": itemApplied, "c": itemRejected, "d": itemNeedsReview, "e": itemNeedsReview},
		states(p), "each its own state (CP21)")
	require.Eventually(t, func() bool { // a tightening item: its intent before its transaction, its conclusion in it (item 4 T6a)
		ev := evidenceFor(w, x.(string))
		return len(ev["intent"]) == 1 && len(ev["effective"]) == 1 && ev["intent"][0]["id"] == ev["effective"][0]["id"]
	}, 10*time.Second, 100*time.Millisecond, "the plan's tightening item's evidence")
	assert.Equal(t, "executing", p["plan_state"], "items to review keep it open")
	assert.Equal(t, "revoked", recordOf(t, admin, x).EndReason)
	assert.Nil(t, items(p)["d"]["record"], "row 17: nothing saved")
	saved := items(p)["e"]["record"]
	require.NotNil(t, saved, "row 20: the unit saved, awaiting its confirmation")

	// the saved unit confirmed: its record takes effect and the item follows it, not run again (CP109)
	code, c := call(t, w, judy, "POST", "/api/authz/confirmations", map[string]any{"target": saved})
	require.Equal(t, 201, code, "%v", c)
	until(id, "e follows its record", func(p map[string]any) bool { return states(p)["e"] == itemApplied })

	// d reviewed with new content (Z instead of the revoked Y): a second person confirms the new attempt; that person
	// no longer qualified when it runs, it is to be reviewed again (CP76)
	_, err := admin.Exec(ctx, "UPDATE "+itSchema+".authz_plan SET second_confirmer = $2 WHERE id = $1", id, carol)
	require.NoError(t, err)
	review := func(attempt int) {
		plan("/"+id.(string)+"/items/d/review", map[string]any{"request": tightenReq("", z),
			"confirmation_ids": []string{confirmPlan(id, fmt.Sprintf("d#%d", attempt))}}, 200)
	}
	plan("/"+id.(string)+"/items/d/review", map[string]any{"request": tightenReq("", z)}, 202) // no confirmation
	review(2)
	p = until(id, "d run, its confirmer not qualified", func(p map[string]any) bool { return items(p)["d"]["reason"] == "confirmation_invalid" })
	assert.Equal(t, itemNeedsReview, states(p)["d"])
	assert.Equal(t, "active", recordOf(t, admin, z).State)
	_, err = admin.Exec(ctx, "UPDATE "+itSchema+".authz_plan SET second_confirmer = $2 WHERE id = $1", id, judy)
	require.NoError(t, err)
	review(3)
	p = until(id, "the plan ends", func(p map[string]any) bool { return p["plan_state"] == planPartial })
	assert.EqualValues(t, 3, items(p)["d"]["attempt"])
	assert.Equal(t, "revoked", recordOf(t, admin, z).EndReason)
	plan("/"+id.(string)+"/cancel", nil, 409) // ended
	e.planEnds()
}

// planEnds is the rest of T7d: a plan cancelled while it executes and before it runs, expired (CP34), a target
// renamed after the preview, a run past the expiry, and a preview over the comparison budget.
func (e *e2e) planEnds() {
	t, w, admin, ctx, root := e.t, e.w, e.admin, e.ctx, e.root
	pt := planTest{e}
	seg, grant, plan, items, until, states := pt.seg, pt.grant, pt.plan, pt.items, pt.until, pt.states
	var p map[string]any
	var digest string
	var err error

	// cancelled while executing: what is to be reviewed ends (not reviewed), with the record it saved; cancelled
	// before it runs: every item ends (plan terminated)
	v := submitChange(t, w, sectest.Alice, grantReq("pl-v", root, carol, append(seg("east"), seg("west")...)), 200)["record"]
	two := plan("", map[string]any{"plan_key": "pl2", "items": []any{
		item("f", unitReq("", root, "pl-unit-2", seg("east"), []string{"demo.order.read"})), item("g", tightenReq("", v))}}, 201)["id"]
	digest = plan("/"+two.(string)+"/preview", nil, 200)["preview_digest"].(string)
	narrowed := tightenReq("pl-v-narrow", v) // after the preview: g's target narrowed, still active (CP03)
	raw, _ := json.Marshal(map[string]any{"governance_unit": root, "grantee": carol, "segments": seg("east")})
	narrowed["candidate"], narrowed["candidate_digest"] = json.RawMessage(raw), candidateDigest("grant", raw)
	submitChange(t, w, sectest.Alice, narrowed, 200)
	plan("/"+two.(string)+"/confirm", map[string]any{"preview_digest": digest}, 200)
	p = until(two, "both to be reviewed", func(p map[string]any) bool {
		s := states(p)
		return s["f"] == itemNeedsReview && s["g"] == itemNeedsReview
	})
	unit2 := items(p)["f"]["record"]
	assert.Equal(t, "active", recordOf(t, admin, v).State, "g's target only narrowed")
	plan("/"+two.(string)+"/items/f/review", map[string]any{}, 409) // saved: its record is confirmed, the item not run again
	p = plan("/"+two.(string)+"/cancel", nil, 200)
	assert.Equal(t, planCancelled, p["plan_state"])
	assert.Equal(t, map[string]string{"f": itemRejected, "g": itemRejected}, states(p))
	assert.Equal(t, "not_reviewed", items(p)["g"]["reason"])
	assert.Equal(t, "cancelled", recordOf(t, admin, unit2).EndReason, "the unit the plan saved ends with it")
	three := plan("", map[string]any{"plan_key": "pl3", "items": []any{item("h", grantReq("", root, pia, seg("east")))}}, 201)["id"]
	plan("/"+three.(string)+"/preview", nil, 200)
	p = plan("/"+three.(string)+"/cancel", nil, 200)
	assert.Equal(t, "plan_terminated", items(p)["h"]["reason"])

	// expired with one item to be reviewed and one applied: the plan expires, the item to be reviewed ends, the
	// applied one stays (CP34)
	u := grant("pl-u", carol, "east")
	four := plan("", map[string]any{"plan_key": "pl4", "items": []any{
		item("i", grantReq("", root, pia, seg("west"))), item("j", tightenReq("", u))}}, 201)["id"]
	digest = plan("/"+four.(string)+"/preview", nil, 200)["preview_digest"].(string)
	submitChange(t, w, sectest.Alice, tightenReq("pl-u-off", u), 200)
	plan("/"+four.(string)+"/confirm", map[string]any{"preview_digest": digest}, 200)
	p = until(four, "i applied, j to be reviewed", func(p map[string]any) bool {
		s := states(p)
		return s["i"] == itemApplied && s["j"] == itemNeedsReview
	})
	_, err = admin.Exec(ctx, "UPDATE "+itSchema+".authz_plan SET expires_at = now() WHERE id = $1", four)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, "UPDATE "+itSchema+".be_work_item SET run_at = now() WHERE job = $1 AND args->>'plan' = $2", JobPlanExpiry, four)
	require.NoError(t, err)
	p = until(four, "expired", func(p map[string]any) bool { return p["plan_state"] == planExpired })
	assert.Equal(t, map[string]string{"i": itemApplied, "j": itemRejected}, states(p))
	assert.Equal(t, "not_reviewed", items(p)["j"]["reason"])
	assert.Equal(t, "active", recordOf(t, admin, items(p)["i"]["record"]).State, "applied items stay")

	// a target renamed after the preview: its content revision moved, its state did not: row 17 all the same (CP03)
	u6 := protectBy(t, w, sectest.Alice, judy, unitReq("pl-u6", root, "pl-unit-6", seg("east"), []string{"demo.order.read"}))["record"]
	six := plan("", map[string]any{"plan_key": "pl6", "items": []any{item("m", tightenReq("", u6))}}, 201)["id"]
	digest = plan("/"+six.(string)+"/preview", nil, 200)["preview_digest"].(string)
	raw, _ = json.Marshal(unitDefaults(map[string]any{"name": "pl-unit-6b", "parent": root, "managed_scope": seg("east"),
		"grantable_operations": []string{"demo.order.read"}}))
	submitChange(t, w, sectest.Alice, map[string]any{"change_key": "pl-u6-name", "direction": "neutral", "target": u6,
		"candidate": json.RawMessage(raw), "candidate_digest": candidateDigest("management_unit", raw)}, 200)
	plan("/"+six.(string)+"/confirm", map[string]any{"preview_digest": digest}, 200)
	p = until(six, "m to be reviewed", func(p map[string]any) bool { return states(p)["m"] == itemNeedsReview })
	assert.Equal(t, "active", recordOf(t, admin, u6).State)

	// past its expiry before the expiry job: a run ends the plan instead of running the item
	q := grant("pl-q", carol, "east")
	_, err = admin.Exec(ctx, "UPDATE "+itSchema+".authz_plan SET expires_at = now() WHERE id = $1", six)
	require.NoError(t, err)
	plan("/"+six.(string)+"/items/m/review", map[string]any{"request": tightenReq("", q)}, 200)
	p = until(six, "expired by its run", func(p map[string]any) bool { return p["plan_state"] == planExpired })
	assert.Equal(t, "plan_terminated", items(p)["m"]["reason"])
	assert.Equal(t, "active", recordOf(t, admin, q).State, "not run")

	// over the comparison budget: 130 grants of 8 segments against a unit of 100 is 104,000 comparisons
	var scope []sdkauthz.Segment
	for i := 0; i < 100; i++ {
		scope = append(scope, orderSeg(region(fmt.Sprintf("r%02d", i))))
	}
	wide := protectBy(t, w, sectest.Alice, judy, unitReq("pl-wide", root, "pl-wide", scope, []string{"demo.order.read"}))["record"]
	var many []any
	for i := 0; i < 130; i++ {
		many = append(many, item(fmt.Sprintf("k%03d", i), grantReq("", wide, pia, scope[:budgetGrantSegments])))
	}
	five2 := plan("", map[string]any{"plan_key": "pl5", "items": many}, 201)["id"]
	out := plan("/"+five2.(string)+"/preview", nil, 400)
	assert.Contains(t, out["detail"], "over budget: 104000 atom comparisons", "%v", out)
}
