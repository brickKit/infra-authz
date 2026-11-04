//go:build integration

package authz

import (
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Ivan joins for the cooling-off: an authorization admin of a side unit only, so his cancellation can only be a veto.
const ivan = "0190f3a1-0000-7000-8000-0000000000f9"

// coolingOff is security 08's cooling-off (A127): a protected widening the deployment owner confirmed while another
// authorization admin became unavailable within the cooling-off waits as scheduled until it ends (CP113), and any
// available admin but its applicant may cancel it meanwhile (a veto, row 7); once it ends it takes effect without
// waiting again; an admin the requester itself made unavailable still counts as available, so the owner's key does
// not stand in (CP108). Every use of the owner's key is audited (the notification, without a channel in this version).
// It runs after the stale phase: Bob is the other admin, Grace and Heidi gave up theirs a moment ago.
func (e *e2e) coolingOff() {
	t, w, admin, ctx, root := e.t, e.w, e.admin, e.ctx, e.root
	scope := []sdkauthz.Segment{orderSeg(region("east"))}
	ops := []string{"demo.order.read"}
	versions := map[string]int64{sectest.Bob: 2, ivan: 1}
	bearerOf := func(who string) string {
		if v, ok := versions[who]; ok {
			return "Bearer " + w.TokenAt(who, v)
		}
		return w.Bearer(who)
	}
	status := func(who, st string) { // the identity member changes an account; the member applies it
		t.Helper()
		versions[who]++
		require.NoError(t, e.iam.set(ctx, who, st, versions[who]))
		require.Eventually(t, func() bool {
			var got string
			_ = admin.QueryRow(ctx, "SELECT coalesce(data->>'status', '') FROM "+itSchema+
				".be_projection WHERE projection = 'accounts' AND record_id = $1", who).Scan(&got)
			return got == st
		}, 10*time.Second, 100*time.Millisecond, "the member applied %s's status %s", who, st)
	}
	confirmedBy := func(who string, record any) {
		t.Helper()
		code, out := callAs(t, bearerOf(who), "POST", "/api/authz/confirmations", map[string]any{"target": record})
		require.Equal(t, 201, code, "%v", out)
		require.Eventually(t, func() bool { return recordOf(t, admin, record).State == "active" }, 10*time.Second,
			50*time.Millisecond, "confirmed: applied")
	}
	settled := func(record any) recordState { // the member's job for it has run
		t.Helper()
		require.Eventually(t, func() bool {
			var busy int
			_ = admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".be_work_item WHERE job = $1 AND args->>'record' = $2"+
				" AND state <> 'done' AND run_at <= now()", JobDue, record).Scan(&busy)
			return busy == 0
		}, 10*time.Second, 50*time.Millisecond)
		return recordOf(t, admin, record)
	}
	age := func(holders ...string) { // their admin holdings ended a day ago: outside the cooling-off
		t.Helper()
		_, err := admin.Exec(ctx, "UPDATE "+itSchema+".authz_record SET updated_at = now() - interval '25 hours'"+
			" WHERE record_type = 'management_holding' AND state <> 'active' AND body->>'holder' = ANY($1)", holders)
		require.NoError(t, err)
	}
	audited := func(record any, action string) int {
		var n int
		require.NoError(t, admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".be_audit_log WHERE target->>'id' = $1"+
			" AND changes->>'action' = $2", record, action).Scan(&n))
		return n
	}

	// Ivan: an authorization admin of a side unit, who may tighten records (Bob confirms both: he is available)
	require.NoError(t, e.iam.set(ctx, ivan, "active", 1))
	side := submitChange(t, w, sectest.Alice, unitReq("co1", root, "side", scope, ops), 202)
	confirmedBy(sectest.Bob, side["record"])
	ivanAdmin := submitChange(t, w, sectest.Alice, widenReq("co2", "management_holding",
		map[string]any{"unit": side["record"], "holder": ivan, "system_role": "authorization_admin"}), 202)
	confirmedBy(sectest.Bob, ivanAdmin["record"])
	segs := []sdkauthz.Segment{}
	for _, op := range []string{OpRead, OpTighten} {
		segs = append(segs, sdkauthz.Segment{ResourceType: Records, Operation: op, Atoms: map[string]sdkauthz.Atom{Holder: {Kind: "all"}},
			ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}})
	}
	submitChange(t, w, sectest.Alice, grantReq("co3", root, ivan, segs), 200)
	waitForView(t, w, ivan)

	// both other admins frozen at the identity member: the owner's key stands in, but their unavailability is recent
	// (when it began is not known here): the widening waits out the cooling-off (CP113)
	status(sectest.Bob, "security_frozen")
	status(ivan, "security_frozen")
	cool := submitChange(t, w, sectest.Alice, unitReq("co4", root, "cooling", scope, ops), 202)
	ownerConfirm(t, w, sectest.Alice, cool["record"], "")
	assert.Equal(t, "scheduled", settled(cool["record"]).State, "confirmed, but it waits out the cooling-off")
	var until time.Time
	require.NoError(t, admin.QueryRow(ctx, "SELECT cooling_off_until FROM "+itSchema+".authz_record WHERE id = $1",
		cool["record"]).Scan(&until))
	assert.WithinDuration(t, time.Now().Add(CoolingOff), until, time.Minute, "a whole cooling-off from now")
	assert.Equal(t, 1, audited(cool["record"], "cooling_off"), "the admins are told (the audit, without a channel)")
	assert.Equal(t, 1, audited(cool["record"], "owner_confirmation"), "every use of the owner's key is told")

	// Ivan is available again: he vetoes it, though he does not manage the root (row 7)
	status(ivan, "active")
	veto := func(key string, target any) (int, map[string]any) {
		return callAs(t, bearerOf(ivan), "POST", "/api/authz/tightenings", map[string]any{"change_key": key, "direction": "tighten",
			"termination": "cancel", "target": target, "expected_state_revision": map[string]any{"domain": "authz.record.state",
				"value": itoa64(int64(recordOf(t, admin, target).StateRev))}})
	}
	var code int
	var out map[string]any
	require.Eventually(t, func() bool { // his account reaches the member's own view
		code, out = veto("co5", cool["record"])
		return code == 200
	}, 10*time.Second, 200*time.Millisecond, "%v", out)
	assert.Equal(t, "cancelled", recordOf(t, admin, cool["record"]).EndReason)
	// outside a cooling-off he manages nothing there: a scheduled grant of the root is not his to cancel
	later := scheduledGrant("co6", root, grace, scope, time.Hour)
	pending := submitChange(t, w, sectest.Alice, later, 202)
	code, out = veto("co7", pending["record"])
	require.Equal(t, 403, code, "%v", out)
	submitChange(t, w, sectest.Alice, map[string]any{"change_key": "co8", "direction": "tighten", "termination": "withdraw",
		"target": pending["record"], "expected_state_revision": map[string]any{"domain": "authz.record.state", "value": "1"}}, 200)

	// once the cooling-off is over it takes effect, without waiting again (the clock moved by the database). Grace's
	// and Heidi's holdings ended a day ago now: the frozen accounts alone call for the cooling-off
	age(grace, heidi)
	status(ivan, "security_frozen")
	done := submitChange(t, w, sectest.Alice, unitReq("co9", root, "cooled", scope, ops), 202)
	ownerConfirm(t, w, sectest.Alice, done["record"], "")
	require.Equal(t, "scheduled", settled(done["record"]).State)
	_, err := admin.Exec(ctx, "UPDATE "+itSchema+".authz_record SET effective_at = now(), cooling_off_until = now() WHERE id = $1",
		done["record"])
	require.NoError(t, err)
	_, err = admin.Exec(ctx, "UPDATE "+itSchema+".be_work_item SET run_at = now() WHERE job = $1 AND args->>'record' = $2"+
		" AND state IN ('pending', 'retry_wait')", JobDue, done["record"])
	require.NoError(t, err)
	require.Eventually(t, func() bool { return recordOf(t, admin, done["record"]).State == "active" }, 10*time.Second,
		100*time.Millisecond, "the cooling-off ended: applied")

	// Alice ends Ivan's admin holding herself (the owner confirms the protected tightening): within the cooling-off he
	// still counts as available, so the owner's key does not stand in for her next protected widening (CP108)
	byOwner := ownerConfirm(t, w, sectest.Alice, ivanAdmin["record"], "1")
	r := tightenReq("co10", ivanAdmin["record"])
	r["confirmation_ids"] = []any{byOwner["id"]}
	submitChange(t, w, sectest.Alice, r, 200)
	blocked := submitChange(t, w, sectest.Alice, unitReq("co11", root, "blocked", scope, ops), 202)
	ownerConfirm(t, w, sectest.Alice, blocked["record"], "")
	assert.Equal(t, "awaiting_confirmation", settled(blocked["record"]).State, "an independent person must confirm")
	withdraw := func(key string, record any) {
		t.Helper()
		submitChange(t, w, sectest.Alice, map[string]any{"change_key": key, "direction": "tighten", "termination": "withdraw",
			"target": record, "expected_state_revision": map[string]any{"domain": "authz.record.state",
				"value": itoa64(int64(recordOf(t, admin, record).StateRev))}}, 200)
	}
	withdraw("co12", blocked["record"])

	// a day later Ivan's end no longer holds Alice back; Bob, active again, gives up his admin holding himself: a
	// holding that ended within the cooling-off alone calls for it
	age(ivan)
	status(sectest.Bob, "active")
	require.Eventually(t, func() bool {
		code, out = callAs(t, bearerOf(sectest.Bob), "POST", "/api/authz/relinquishments", tightenReq("co15", bobsAdminHolding(t, admin)))
		return code == 200
	}, 10*time.Second, 200*time.Millisecond, "%v", out)
	ended := submitChange(t, w, sectest.Alice, unitReq("co16", root, "after-bob", scope, ops), 202)
	ownerConfirm(t, w, sectest.Alice, ended["record"], "")
	assert.Equal(t, "scheduled", settled(ended["record"]).State, "Bob's holding ended a moment ago")

	// what this phase made goes away
	withdraw("co17", ended["record"])
	submitChange(t, w, sectest.Alice, tightenReq("co13", done["record"]), 200)
	submitChange(t, w, sectest.Alice, tightenReq("co14", side["record"]), 200)
}
