//go:build integration

package itest

import (
	"context"
	"testing"
	"time"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// itTight is AUTHZ_T_TIGHT in the end-to-end run: long enough that a tightening reaches the effect point between
// D_src_high (3 s) and it, short enough to wait past it.
const itTight = 10 * time.Second

// Grace and Heidi join after the identity phase (it changed the accounts of Bob, Carol, Dave and Eve); Paula is an
// ordinary account whose disablement the identity member asks about.
const (
	grace = "0190f3a1-0000-7000-8000-0000000000f7"
	heidi = "0190f3a1-0000-7000-8000-0000000000f8"
	paula = "0190f3a1-0000-7000-8000-0000000000e9"
)

// bearer is who's token after the identity phase: Bob's account is at security version 2 since.
func bearer(w *sectest.World, who string) string {
	if who == sectest.Bob {
		return "Bearer " + w.TokenAt(sectest.Bob, 2)
	}
	return w.Bearer(who)
}

// bobsAdminHolding is Bob's active authorization admin holding (testProtected gives it back to him at its end).
func bobsAdminHolding(t *testing.T, admin *pgx.Conn) string {
	var id string
	require.NoError(t, admin.QueryRow(context.Background(), "SELECT id::text FROM "+itSchema+`.authz_record
		WHERE state = 'active' AND record_type = 'management_holding' AND body->>'holder' = $1
			AND body->>'system_role' = 'authorization_admin'`, sectest.Bob).Scan(&id))
	return id
}

// staleTightening is T5e (security 03's tightening-only operations, A125, P8.29, P9.34): with the identity source
// stopped, tightenings stay possible on the source's last applied facts. Within T_tight one person revokes alone
// (AT57, CP36); beyond it a second authorization admin, judged by the last applied facts too, confirms first (AT61,
// CP80), or the deployment owner does (AT64); a tightening that touches an authorization admin's availability (the
// holding, a unit one sits in, or a unit above that) waits for a requester or confirmer proven now (AT58, row 12). Each says "basis not
// proven latest" in its result and its audit. Widenings go to their own route, never this one. It runs after the
// identity phase, which leaves the identity member stopped: it starts it again first.
func (e *e2e) staleTightening() {
	t, w, admin, ctx, root := e.t, e.w, e.admin, e.ctx, e.root
	seg := []sdkauthz.Segment{orderSeg(region("east"))}
	e.iam, e.stopIAM = startIAM(t, w, e.pgPassword, e.busURL, false)
	for _, p := range []string{grace, heidi, paula} {
		require.NoError(t, e.iam.set(ctx, p, "active", 1))
	}
	revoke := func(key string, target any, ids ...any) (int, map[string]any) {
		r := tightenReq(key, target)
		if len(ids) > 0 {
			r["confirmation_ids"] = ids
		}
		return call(t, w, sectest.Alice, "POST", "/api/authz/tightenings", r)
	}

	// Bob is the second authorization admin; a unit under the root with an admin holding in it, and four ordinary
	// grants. The member's own view renews fully once the identity member answers again: widenings go on after it
	bobAdmin := map[string]any{"record": bobsAdminHolding(t, admin)}
	var unit map[string]any
	require.Eventually(t, func() bool {
		var code int
		code, unit = call(t, w, sectest.Alice, "POST", "/api/authz/changes", unitReq("st2", root, "stale", seg, []string{"demo.order.read"}))
		return code == 202
	}, 15*time.Second, 200*time.Millisecond, "a widening once the source answers: %v", unit)
	confirmed := func(record any) {
		t.Helper()
		confirmAs(t, w, sectest.Bob, record, "")
		require.Eventually(t, func() bool { return recordOf(t, admin, record).State == "active" }, 10*time.Second,
			50*time.Millisecond, "confirmed by Bob: applied")
	}
	confirmed(unit["record"])
	sub := submitChange(t, w, sectest.Alice, subUnitReq("st2s", unit["record"], "stale-sub", seg, []string{"demo.order.read"}), 202)
	confirmed(sub["record"])
	graceAdmin := submitChange(t, w, sectest.Alice, widenReq("st3", "management_holding",
		map[string]any{"unit": sub["record"], "holder": grace, "system_role": "authorization_admin"}), 202)
	confirmed(graceAdmin["record"])
	var g [4]map[string]any
	for i := range g {
		g[i] = submitChange(t, w, sectest.Alice, grantReq("st-g"+itoa64(int64(i)), root, grace, seg), 200)
	}
	// Bob confirms ending the sub-unit while the source answers: attached later, he must be proven then (row 22); so
	// does his confirmation of disabling Heidi's account, an admin's (CP92)
	subByBob := confirmAs(t, w, sectest.Bob, sub["record"], "1")
	code, heidiByBob := callAs(t, bearer(w, sectest.Bob), "POST", "/api/authz/confirmations", map[string]any{"account": heidi,
		"target_state": "disabled", "target_state_version": 1}) // her status may not be projected yet: the version named
	require.Equal(t, 201, code, "%v", heidiByBob)

	// a confirmation needs the operation of what it confirms: Heidi, an authorization admin who may read and tighten
	// records but not change them, confirms a tightening, not a saved widening
	heidiAdmin := submitChange(t, w, sectest.Alice, widenReq("st3d", "management_holding",
		map[string]any{"unit": root, "holder": heidi, "system_role": "authorization_admin"}), 202)
	confirmed(heidiAdmin["record"])
	heidiSegs := []sdkauthz.Segment{}
	for _, op := range []string{core.OpRead, core.OpTighten} {
		heidiSegs = append(heidiSegs, sdkauthz.Segment{ResourceType: core.Records, Operation: op,
			Atoms: map[string]sdkauthz.Atom{core.Holder: {Kind: "all"}}, ReadFields: []string{"id"},
			Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}})
	}
	heidiGrant := submitChange(t, w, sectest.Alice, grantReq("st3g", root, heidi, heidiSegs), 200)
	waitForView(t, w, heidi)
	pending := submitChange(t, w, sectest.Alice, unitReq("st3p", root, "pending", seg, []string{"demo.order.read"}), 202)
	code, out := call(t, w, heidi, "POST", "/api/authz/confirmations", map[string]any{"target": pending["record"]})
	require.Contains(t, []int{403, 404}, code, "a saved widening's confirmation is a change: %v", out)
	confirmAs(t, w, heidi, g[3]["record"], "1")

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
	op, basis := lastAudit(t, admin, g[0]["record"])
	assert.Equal(t, core.OpTighten, op)
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
	// a confirmer whose eligibility cannot be proven now rejects a pending widening: processing, nothing changes
	// (CP104, row 9)
	code, out = callAs(t, bearer(w, sectest.Bob), "POST", "/api/authz/tightenings", map[string]any{"change_key": "st6r",
		"direction": "tighten", "termination": "reject", "target": pending["record"],
		"expected_state_revision": map[string]any{"domain": "authz.record.state", "value": "1"}})
	require.Equal(t, 202, code, "%v", out)
	assert.Equal(t, "ADMIN_AVAILABILITY_UNPROVABLE", out["reason"])
	assert.Equal(t, "awaiting_confirmation", recordOf(t, admin, pending["record"]).State)
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
	byBob := confirmAs(t, w, sectest.Bob, g[1]["record"], "1")
	code, out = revoke("st7", g[1]["record"], byBob["id"])
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "last_applied", out["basis"])
	assert.Equal(t, "ended", recordOf(t, admin, g[1]["record"]).State)
	_, basis = lastAudit(t, admin, g[1]["record"])
	assert.Equal(t, "not_proven_latest", basis)
	// an account's status beyond T_tight (A134): the identity member asks for a second person; Bob, judged by the last
	// applied facts, confirms disabling an ordinary account (CP80's account form); an admin's account needs a
	// confirmer proven now: not provable, nothing is decided and the identity member answers processing (CP92)
	accounts := authzv3.NewAccountServiceClient(dial(t, w, iamID))
	accountCheck := func(account, conf string) authzv3.AccountChangeVerdict {
		t.Helper()
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		out, err := accounts.CheckAccountChange(cctx, &authzv3.CheckAccountChangeRequest{Account: account, TargetState: "disabled",
			SecurityVersion: 1, Requester: sectest.Alice, Confirmation: conf, SecondPerson: true})
		require.NoError(t, err)
		return out.GetVerdict()
	}
	byBobFor := func(account string) string {
		t.Helper()
		code, out := callAs(t, bearer(w, sectest.Bob), "POST", "/api/authz/confirmations", map[string]any{"account": account,
			"target_state": "disabled"})
		require.Equal(t, 201, code, "%v", out)
		return out["id"].(string)
	}
	assert.Equal(t, authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_CONFIRMATION_REQUIRED, accountCheck(paula, ""))
	assert.Equal(t, authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_ALLOWED, accountCheck(paula, byBobFor(paula)), "CP80")
	code, out = callAs(t, bearer(w, sectest.Bob), "POST", "/api/authz/confirmations", map[string]any{"account": heidi,
		"target_state": "disabled"})
	assert.Equal(t, 503, code, "an admin's account: the confirmer must be proven now (CP92): %v", out)
	assert.Equal(t, "AUTHORIZATION_UNPROVABLE", out["reason"])
	assert.Equal(t, authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_UNPROVABLE, accountCheck(heidi, heidiByBob["id"].(string)),
		"made while Bob was proven, judged now: not provable, nothing decided (CP92)")

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
	_, basis = lastAudit(t, admin, g[3]["record"])
	assert.Empty(t, basis)

	e.staleCleanup(pending["record"], heidiGrant["record"], graceAdmin["record"], heidiAdmin["record"], sub["record"], unit["record"])
}

// staleCleanup takes away what the stale-tightening phase made: the pending unit, Heidi's grant; Grace and Heidi give
// up their admin holdings themselves (the cooling-off phase counts them as admins who became unavailable, not by
// Alice); the units. Bob stays an admin. The member's own view renews for high-risk operations at its next
// verification: widenings go on after it.
func (e *e2e) staleCleanup(pending, heidiGrant, graceAdmin, heidiAdmin, sub, unit any) {
	t, w, root := e.t, e.w, e.root
	var code int
	var out map[string]any
	submitChange(t, w, sectest.Alice, map[string]any{"change_key": "st10p", "direction": "tighten", "termination": "withdraw",
		"target": pending, "expected_state_revision": map[string]any{"domain": "authz.record.state", "value": "1"}}, 200)
	submitChange(t, w, sectest.Alice, tightenReq("st10g", heidiGrant), 200)
	for _, h := range []struct {
		who    string
		record any
	}{{grace, graceAdmin}, {heidi, heidiAdmin}} {
		require.Eventually(t, func() bool {
			code, out = call(t, w, h.who, "POST", "/api/authz/relinquishments", tightenReq("st10-"+h.who, h.record))
			return code == 200
		}, 10*time.Second, 200*time.Millisecond, "%v", out)
	}
	submitChange(t, w, sectest.Alice, tightenReq("st11s", sub), 200)
	submitChange(t, w, sectest.Alice, tightenReq("st11", unit), 200)
	var again map[string]any
	require.Eventually(t, func() bool {
		code, again = call(t, w, sectest.Alice, "POST", "/api/authz/changes", grantReq("st12", root, grace, []sdkauthz.Segment{orderSeg(region("east"))}))
		return code == 200
	}, 10*time.Second, 200*time.Millisecond, "a widening once the source answers: %v", again)
	submitChange(t, w, sectest.Alice, tightenReq("st13", again["record"]), 200)
}

// confirmAs is a confirmation by another person, of a saved widening or (with its revision) of a tightening.
func confirmAs(t *testing.T, w *sectest.World, who string, target any, revision string) map[string]any {
	t.Helper()
	body := map[string]any{"target": target}
	if revision != "" {
		body["expected_revision"] = map[string]any{"domain": "authz.record.revision", "value": revision}
	}
	code, out := callAs(t, bearer(w, who), "POST", "/api/authz/confirmations", body)
	require.Equal(t, 201, code, "%v", out)
	return out
}

// lastAudit is the last security change audited on a record: the operation that admitted it and its basis.
func lastAudit(t *testing.T, admin *pgx.Conn, record any) (op, basis string) {
	t.Helper()
	require.NoError(t, admin.QueryRow(context.Background(), "SELECT operation, coalesce(changes->>'basis', '') FROM "+itSchema+
		".be_audit_log WHERE category = 'security_change' AND target->>'id' = $1 ORDER BY ord DESC LIMIT 1",
		record).Scan(&op, &basis))
	return op, basis
}
