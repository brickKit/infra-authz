//go:build integration

package authz

import (
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// itTight is AUTHZ_T_TIGHT in the end-to-end run: long enough that a tightening reaches the effect point between
// D_src_high (3 s) and it, short enough to wait past it.
const itTight = 10 * time.Second

// staleTightening is T5e (security 03's tightening-only operations, A125, P8.29, P9.34): with the identity source
// stopped, tightenings stay possible on the source's last applied facts. Within T_tight one person revokes alone
// (AT57, CP36); beyond it a second authorization admin, judged by the last applied facts too, confirms first (AT61,
// CP80), or the deployment owner does (AT64); a tightening that touches an authorization admin's availability (the
// holding, a unit one sits in, or a unit above that) waits for a requester or confirmer proven now (AT58, row 12). Each says "basis not
// proven latest" in its result and its audit. Widenings go to their own route, never this one.
func (e *e2e) staleTightening() {
	t, w, admin, ctx, root := e.t, e.w, e.admin, e.ctx, e.root
	seg := []sdkauthz.Segment{orderSeg(region("east"))}
	confirmBy := func(who string, target any, revision string) map[string]any {
		t.Helper()
		body := map[string]any{"target": target}
		if revision != "" {
			body["expected_revision"] = map[string]any{"domain": "authz.record.revision", "value": revision}
		}
		code, out := call(t, w, who, "POST", "/api/authz/confirmations", body)
		require.Equal(t, 201, code, "%v", out)
		return out
	}
	revoke := func(key string, target any, ids ...any) (int, map[string]any) {
		r := tightenReq(key, target)
		if len(ids) > 0 {
			r["confirmation_ids"] = ids
		}
		return call(t, w, sectest.Alice, "POST", "/api/authz/tightenings", r)
	}
	auditOf := func(record any) (op, basis string) {
		t.Helper()
		require.NoError(t, admin.QueryRow(ctx, "SELECT operation, coalesce(changes->>'basis', '') FROM "+itSchema+
			".be_audit_log WHERE category = 'security_change' AND target->>'id' = $1 ORDER BY ord DESC LIMIT 1",
			record).Scan(&op, &basis))
		return op, basis
	}

	// a second authorization admin, a unit under the root with an admin holding in it, and four ordinary grants
	bobAdmin := protect(t, w, sectest.Alice, widenReq("st1", "management_holding",
		map[string]any{"unit": root, "holder": sectest.Bob, "system_role": "authorization_admin"}))
	waitForView(t, w, sectest.Bob)
	unit := submitChange(t, w, sectest.Alice, unitReq("st2", root, "stale", seg, []string{"demo.order.read"}), 202)
	confirmed := func(record any) {
		t.Helper()
		confirmBy(sectest.Bob, record, "")
		require.Eventually(t, func() bool { return recordOf(t, admin, record).State == "active" }, 10*time.Second,
			50*time.Millisecond, "confirmed by Bob: applied")
	}
	confirmed(unit["record"])
	sub := submitChange(t, w, sectest.Alice, unitReq("st2s", unit["record"], "stale-sub", seg, []string{"demo.order.read"}), 202)
	confirmed(sub["record"])
	carolAdmin := submitChange(t, w, sectest.Alice, widenReq("st3", "management_holding",
		map[string]any{"unit": sub["record"], "holder": carol, "system_role": "authorization_admin"}), 202)
	confirmed(carolAdmin["record"])
	var g [4]map[string]any
	for i := range g {
		g[i] = submitChange(t, w, sectest.Alice, grantReq("st-g"+itoa64(int64(i)), root, carol, seg), 200)
	}
	// Bob confirms ending the sub-unit while the source answers: attached later, he must be proven then (row 22)
	subByBob := confirmBy(sectest.Bob, sub["record"], "1")

	// a confirmation needs the operation of what it confirms: Dave, an authorization admin who may read and tighten
	// records but not change them, confirms a tightening, not a saved widening
	daveAdmin := submitChange(t, w, sectest.Alice, widenReq("st3d", "management_holding",
		map[string]any{"unit": root, "holder": dave, "system_role": "authorization_admin"}), 202)
	confirmed(daveAdmin["record"])
	daveSegs := []sdkauthz.Segment{}
	for _, op := range []string{OpRead, OpTighten} {
		daveSegs = append(daveSegs, sdkauthz.Segment{ResourceType: Records, Operation: op,
			Atoms: map[string]sdkauthz.Atom{Holder: {Kind: "all"}}, ReadFields: []string{"id"},
			Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}})
	}
	daveGrant := submitChange(t, w, sectest.Alice, grantReq("st3g", root, dave, daveSegs), 200)
	waitForView(t, w, dave)
	pending := submitChange(t, w, sectest.Alice, unitReq("st3p", root, "pending", seg, []string{"demo.order.read"}), 202)
	code, out := call(t, w, dave, "POST", "/api/authz/confirmations", map[string]any{"target": pending["record"]})
	require.Contains(t, []int{403, 404}, code, "a saved widening's confirmation is a change: %v", out)
	confirmBy(dave, g[3]["record"], "1")

	// a tightening has its own operation and route: the changes refuse it
	code, out = call(t, w, sectest.Alice, "POST", "/api/authz/changes", tightenReq("st4", g[0]["record"]))
	require.Equal(t, 400, code, "%v", out)
	assert.Equal(t, "REQUEST_INVALID", out["reason"])

	// the identity source stops; past D_src_high (the member's own view renews for ordinary reads only) the requester
	// is no longer proven now
	e.stopIAM()
	stopped := time.Now()
	held := e.held
	readOnly := func() bool {
		ans := e.verify(held)
		if ans.Shards[0].Status == "changed" {
			held.Digest = ans.Shards[0].View.Digest
		}
		return ans.Shards[0].Status == "closed" || ans.Shards[0].ReadOnly
	}
	require.Eventually(t, readOnly, 10*time.Second, 100*time.Millisecond, "the source past D_src_high")

	// within T_tight: one person, on the last applied facts (AT57, CP36)
	code, out = revoke("st5", g[0]["record"])
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "last_applied", out["basis"], "the result says its basis is not proven latest")
	assert.Equal(t, "ended", recordOf(t, admin, g[0]["record"]).State)
	op, basis := auditOf(g[0]["record"])
	assert.Equal(t, OpTighten, op)
	assert.Equal(t, "not_proven_latest", basis, "so does the audit")
	// another admin's holding, the unit an admin holding sits in, or a unit above it: not on old facts alone (AT58,
	// row 12)
	for _, target := range []any{bobAdmin["record"], sub["record"], unit["record"]} {
		code, out = revoke("st6-"+target.(string), target)
		require.Equal(t, 202, code, "%v", out)
		assert.Equal(t, "processing", out["outcome"])
		assert.Equal(t, "ADMIN_AVAILABILITY_UNPROVABLE", out["reason"])
		assert.Equal(t, "active", recordOf(t, admin, target).State)
	}
	code, out = revoke("st6c", sub["record"], subByBob["id"])
	require.Equal(t, 202, code, "%v", out)
	assert.Equal(t, "ADMIN_AVAILABILITY_UNPROVABLE", out["reason"], "its confirmer not proven now either (row 22)")
	assert.Equal(t, "active", recordOf(t, admin, sub["record"]).State)

	// beyond T_tight: a second person first (AT61, CP80), judged by the last applied facts too
	time.Sleep(time.Until(stopped.Add(itTight + time.Second)))
	code, out = revoke("st7", g[1]["record"])
	require.Equal(t, 202, code, "%v", out)
	assert.Equal(t, "awaiting_confirmation", out["outcome"])
	assert.Equal(t, "CONFIRMATION_REQUIRED", out["reason"])
	assert.Equal(t, "active", recordOf(t, admin, g[1]["record"]).State, "nothing saved, nothing changed")
	byBob := confirmBy(sectest.Bob, g[1]["record"], "1")
	code, out = revoke("st7", g[1]["record"], byBob["id"])
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "last_applied", out["basis"])
	assert.Equal(t, "ended", recordOf(t, admin, g[1]["record"]).State)
	_, basis = auditOf(g[1]["record"])
	assert.Equal(t, "not_proven_latest", basis)
	// the deployment owner stands in for the second person (AT64)
	byOwner := ownerConfirm(t, w, sectest.Alice, g[2]["record"], "1")
	code, out = revoke("st8", g[2]["record"], byOwner["id"])
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "ended", recordOf(t, admin, g[2]["record"]).State)

	// the source answers again: proven now, one person, nothing to mark
	e.iam, e.stopIAM = startIAM(t, w, e.pgPassword, e.busURL, false)
	require.Eventually(t, func() bool { return !readOnly() }, 15*time.Second, 200*time.Millisecond, "renewed fully again")
	e.held = held
	require.Eventually(t, func() bool {
		code, out = revoke("st9", g[3]["record"])
		return code == 200
	}, 10*time.Second, 200*time.Millisecond, "%v", out)
	assert.Nil(t, out["basis"], "proven now")
	_, basis = auditOf(g[3]["record"])
	assert.Empty(t, basis)

	// what this phase made goes away: the pending unit, Dave's grant, the other admins' holdings (protected tightenings,
	// the owner confirms), the units
	submitChange(t, w, sectest.Alice, map[string]any{"change_key": "st10p", "direction": "tighten", "termination": "withdraw",
		"target": pending["record"], "expected_state_revision": map[string]any{"domain": "authz.record.state", "value": "1"}}, 200)
	submitChange(t, w, sectest.Alice, tightenReq("st10g", daveGrant["record"]), 200)
	for _, target := range []any{daveAdmin["record"], carolAdmin["record"], bobAdmin["record"]} {
		byOwner := ownerConfirm(t, w, sectest.Alice, target, "1")
		code, out = revoke("st10-"+target.(string), target, byOwner["id"])
		require.Equal(t, 200, code, "%v", out)
	}
	submitChange(t, w, sectest.Alice, tightenReq("st11s", sub["record"]), 200)
	submitChange(t, w, sectest.Alice, tightenReq("st11", unit["record"]), 200)
	// the member's own view renews for high-risk operations at its next verification: widenings go on after it
	var again map[string]any
	require.Eventually(t, func() bool {
		code, again = call(t, w, sectest.Alice, "POST", "/api/authz/changes", grantReq("st12", root, carol, seg))
		return code == 200
	}, 10*time.Second, 200*time.Millisecond, "a widening once the source answers: %v", again)
	submitChange(t, w, sectest.Alice, tightenReq("st13", again["record"]), 200)
}
