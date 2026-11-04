//go:build integration

package authz

import (
	"context"
	"testing"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testConfirmations is T5a (security 08's confirmation records, 09a's be.security.confirmation, A123): another
// authorization admin confirms a tightening of a record at its revision; the requester attaches it; it is used once.
// A confirmation that does not hold (used, someone else's target, the requester's own, the object's own, expired, an
// older revision) is no confirmation: a tightening that carries one waits for a valid one (row 24).
func testConfirmations(t *testing.T, w *sectest.World, admin *pgx.Conn, root string) {
	ctx := context.Background()
	seg := []sdkauthz.Segment{orderSeg(region("east"))}
	confirm := func(who string, target any, revision int64) (int, map[string]any) {
		return call(t, w, who, "POST", "/api/authz/confirmations", map[string]any{"target": target,
			"expected_revision": map[string]any{"domain": "authz.record.revision", "value": itoa64(revision)}})
	}
	revokeWith := func(key string, target any, ids ...any) (int, map[string]any) {
		r := tightenReq(key, target)
		r["confirmation_ids"] = ids
		return call(t, w, sectest.Alice, "POST", "/api/authz/changes", r)
	}

	// only an authorization admin confirms (A123): Bob manages records, holds no such role yet
	g := submitChange(t, w, sectest.Alice, grantReq("cf1", root, carol, seg), 200)
	code, out := confirm(sectest.Bob, g["record"], 1)
	require.Equal(t, 403, code, "%v", out)
	assert.Equal(t, "PERMISSION_DENIED", out["reason"])
	bobAdmin := protect(t, w, sectest.Alice, widenReq("cf2", "management_holding",
		map[string]any{"unit": root, "holder": sectest.Bob, "system_role": "authorization_admin"}))
	waitForView(t, w, sectest.Bob)

	// a valid confirmation: the revocation applies, the confirmation is used by it
	code, c1 := confirm(sectest.Bob, g["record"], 1)
	require.Equal(t, 201, code, "%v", c1)
	code, out = revokeWith("cf3", g["record"], c1["id"])
	require.Equal(t, 200, code, "%v", out)
	var used *string
	require.NoError(t, admin.QueryRow(ctx, "SELECT consumed_by_change FROM "+itSchema+".authz_confirmation WHERE id = $1", c1["id"]).Scan(&used))
	require.NotNil(t, used, "used by the change that applied")
	assert.Equal(t, sectest.Alice+":cf3", *used)

	g2 := submitChange(t, w, sectest.Alice, grantReq("cf4", root, carol, seg), 200)
	waiting := func(key string, ids ...any) {
		t.Helper()
		code, out := revokeWith(key, g2["record"], ids...)
		require.Equal(t, 202, code, "%v", out)
		assert.Equal(t, "awaiting_confirmation", out["outcome"])
		assert.Equal(t, "CONFIRMATION_REQUIRED", out["reason"])
		assert.Equal(t, "active", recordOf(t, admin, g2["record"]).State, "a tightening waiting for its confirmation changes nothing")
	}
	waiting("cf5", c1["id"]) // used already, and for another record
	_, own := confirm(sectest.Alice, g2["record"], 1)
	require.NotEmpty(t, own["id"], "the requester may record a confirmation; it never counts for her own change")
	waiting("cf6", own["id"])
	_, stale := confirm(sectest.Bob, g2["record"], 2)
	waiting("cf7", stale["id"]) // for a revision the record does not have
	_, late := confirm(sectest.Bob, g2["record"], 1)
	_, err := admin.Exec(ctx, "UPDATE "+itSchema+".authz_confirmation SET expires_at = now() - interval '1 second' WHERE id = $1", late["id"])
	require.NoError(t, err)
	waiting("cf8", late["id"])
	code, out = revokeWith("cf9", g2["record"], "01a1a6a0-0000-7000-8000-000000000000")
	require.Equal(t, 202, code, "an unknown confirmation is no confirmation: %v", out)

	// the object of the change never confirms it: Bob's own holding, revoked by Alice with Bob's confirmation
	_, bobs := confirm(sectest.Bob, bobAdmin["record"], 1)
	code, out = revokeWith("cf10", bobAdmin["record"], bobs["id"])
	require.Equal(t, 202, code, "%v", out)
	assert.Equal(t, "active", recordOf(t, admin, bobAdmin["record"]).State)

	// valid in every other way, but for another record
	g3 := submitChange(t, w, sectest.Alice, grantReq("cf12", root, carol, seg), 200)
	_, elsewhere := confirm(sectest.Bob, g3["record"], 1)
	waiting("cf13", elsewhere["id"])

	_, fresh := confirm(sectest.Bob, g2["record"], 1)
	code, out = revokeWith("cf11", g2["record"], fresh["id"])
	require.Equal(t, 200, code, "%v", out)

	// the confirmer is checked again when the change enters: Bob no longer an admin, his confirmation no longer holds
	_, before := confirm(sectest.Bob, g3["record"], 1)
	// another admin's holding is a protected tightening (security 08, item 7): it carries a confirmation first (row
	// 21); the deployment owner's stands in for an independent one on any protected tightening
	code, out = call(t, w, sectest.Alice, "POST", "/api/authz/changes", tightenReq("cf14", bobAdmin["record"]))
	require.Equal(t, 202, code, "%v", out)
	assert.Equal(t, "awaiting_confirmation", out["outcome"], "nothing saved: the request comes again with its confirmation")
	assert.Equal(t, "active", recordOf(t, admin, bobAdmin["record"]).State)
	byOwner := ownerConfirm(t, w, sectest.Alice, bobAdmin["record"], "1")
	code, out = revokeWith("cf14", bobAdmin["record"], byOwner["id"])
	require.Equal(t, 200, code, "%v", out)
	code, out = revokeWith("cf15", g3["record"], before["id"])
	require.Equal(t, 202, code, "%v", out)
	assert.Equal(t, "active", recordOf(t, admin, g3["record"]).State)
	submitChange(t, w, sectest.Alice, tightenReq("cf16", g3["record"]), 200)
	testProtected(t, w, admin, root)
}

// testProtected is T5b-T5d (security 08's protected operations, A124): a new management unit or holding waits for a
// confirmation; with another authorization admin available an independent person must confirm (the owner's key does
// not count for a widening then); once confirmed the member's job applies it, or schedules it when effective later;
// a confirmer may reject it (row 7); the requester is checked again when it enters (CP67).
func testProtected(t *testing.T, w *sectest.World, admin *pgx.Conn, root string) {
	ctx := context.Background()
	ops := []string{"demo.order.read"}
	scope := []sdkauthz.Segment{orderSeg(region("east"))}
	bobAdmin := protect(t, w, sectest.Alice, widenReq("pr1", "management_holding",
		map[string]any{"unit": root, "holder": sectest.Bob, "system_role": "authorization_admin"}))
	waitForView(t, w, sectest.Bob)
	jobsDone := func(record any) {
		t.Helper()
		require.Eventually(t, func() bool {
			var busy int
			_ = admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".be_work_item WHERE job = $1 AND args->>'record' = $2 AND state <> 'done'",
				JobDue, record).Scan(&busy)
			return busy == 0
		}, 10*time.Second, 50*time.Millisecond)
	}

	// Bob is available: the owner's confirmation does not stand in for him on a widening (row 23: still waiting)
	u := submitChange(t, w, sectest.Alice, unitReq("pr2", root, "protected", scope, ops), 202)
	assert.Equal(t, "awaiting_confirmation", recordOf(t, admin, u["record"]).State)
	ownerConfirm(t, w, sectest.Alice, u["record"], "")
	jobsDone(u["record"])
	assert.Equal(t, "awaiting_confirmation", recordOf(t, admin, u["record"]).State, "an independent person must confirm")
	code, out := call(t, w, sectest.Bob, "POST", "/api/authz/confirmations", map[string]any{"target": u["record"]})
	require.Equal(t, 201, code, "%v", out)
	require.Eventually(t, func() bool { return recordOf(t, admin, u["record"]).State == "active" }, 10*time.Second, 50*time.Millisecond,
		"confirmed by Bob: applied by the job")

	// confirmed, effective later: scheduled, then applied when due
	later := widenReq("pr3", "management_holding", map[string]any{"unit": u["record"], "holder": carol})
	later["effective_from"] = time.Now().Add(2 * time.Second).UTC().Format(time.RFC3339Nano)
	h := submitChange(t, w, sectest.Alice, later, 202)
	code, out = call(t, w, sectest.Bob, "POST", "/api/authz/confirmations", map[string]any{"target": h["record"]})
	require.Equal(t, 201, code, "%v", out)
	require.Eventually(t, func() bool { return recordOf(t, admin, h["record"]).State == "scheduled" }, 10*time.Second, 50*time.Millisecond)
	require.Eventually(t, func() bool { return recordOf(t, admin, h["record"]).State == "active" }, 10*time.Second, 100*time.Millisecond,
		"due: applied with its confirmation, checked again")
	var used int
	require.NoError(t, admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".authz_confirmation WHERE target = $1 AND consumed_by_change IS NOT NULL",
		h["record"]).Scan(&used))
	assert.Equal(t, 1, used, "used when it applied, not when it was scheduled")

	// a confirmer rejects a pending one (row 7)
	r := submitChange(t, w, sectest.Alice, unitReq("pr4", root, "rejected", scope, ops), 202)
	submitChange(t, w, sectest.Bob, map[string]any{"change_key": "pr5", "direction": "tighten", "termination": "reject",
		"target": r["record"], "expected_state_revision": map[string]any{"domain": "authz.record.state", "value": "1"}}, 200)
	assert.Equal(t, "rejected", recordOf(t, admin, r["record"]).EndReason)

	// a signature that does not verify is no confirmation; nor does one stretch how long a confirmation holds
	p := submitChange(t, w, sectest.Alice, unitReq("pr6", root, "forged", scope, ops), 202)
	code, out = call(t, w, sectest.Alice, "POST", "/api/authz/confirmations", map[string]any{"target": p["record"],
		"basis": "deployment_owner", "expires_at": time.Now().Add(100 * time.Hour).UTC().Format("2006-01-02T15:04:05.000000Z"),
		"signature": "AAAA"})
	require.Equal(t, 400, code, "beyond the 72 hours a confirmation holds: %v", out)
	// the applicant is no confirmer of her own request: her "rejection" is refused (she withdraws instead)
	code, out = call(t, w, sectest.Alice, "POST", "/api/authz/changes", map[string]any{"change_key": "pr10", "direction": "tighten",
		"termination": "reject", "target": p["record"], "expected_state_revision": map[string]any{"domain": "authz.record.state", "value": "1"}})
	require.Equal(t, 403, code, "%v", out)
	code, out = call(t, w, sectest.Alice, "POST", "/api/authz/confirmations", map[string]any{"target": p["record"],
		"basis": "deployment_owner", "expires_at": time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05.000000Z"),
		"signature": "AAAA"})
	require.Equal(t, 403, code, "%v", out)

	// Bob asks for a unit, then loses his admin holding before Alice confirms it: checked again, rejected (CP67)
	b := submitChange(t, w, sectest.Bob, unitReq("pr7", root, "bobs", scope, ops), 202)
	byOwner := ownerConfirm(t, w, sectest.Alice, bobAdmin["record"], "1")
	rv := tightenReq("pr8", bobAdmin["record"])
	rv["confirmation_ids"] = []any{byOwner["id"]}
	submitChange(t, w, sectest.Alice, rv, 200)
	code, out = call(t, w, sectest.Alice, "POST", "/api/authz/confirmations", map[string]any{"target": b["record"]})
	require.Equal(t, 201, code, "%v", out)
	require.Eventually(t, func() bool { return recordOf(t, admin, b["record"]).State == "ended" }, 10*time.Second, 50*time.Millisecond)
	assert.Equal(t, recordState{State: "ended", EndReason: "rejected", Revision: 1, StateRev: 2, Reason: "PERMISSION_DENIED"},
		recordOf(t, admin, b["record"]))
	for _, id := range []any{p["record"]} {
		submitChange(t, w, sectest.Alice, map[string]any{"change_key": "pr9", "direction": "tighten", "termination": "cancel",
			"target": id, "expected_state_revision": map[string]any{"domain": "authz.record.state", "value": "1"}}, 200)
	}
}
