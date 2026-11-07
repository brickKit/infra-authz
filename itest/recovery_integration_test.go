//go:build integration

package itest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"time"

	adminrecovery "github.com/brickKit/infra-authz/v3/internal/adminrecovery"
	plans "github.com/brickKit/infra-authz/v3/internal/plans"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Olga is restored as an admin while her account is disabled.
const olga = "0190f3a1-0000-7000-8000-0000000000ff"

// recovery is T6f (security 08's administrator recovery, A129): the deployment owner's signed request, used once, is
// the only credential; restore leaves recovery pending with a new generation and an admin holding for the identity
// (CP15); replace holds a compromised admin's holding as the owner's disposition and cancels its pending widenings
// (CP51); a restored identity whose account is not active keeps the deployment in administrator recovery until its
// account is (CP74); abort goes back (CP64); the last admin's account disabled is pending recovery again (CP26). It
// runs after the pending phase.
func (e *e2e) recovery() {
	t, w, admin, ctx, root := e.t, e.w, e.admin, e.ctx, e.root
	recover := func(r adminrecovery.RecoveryRequest, key ed25519.PrivateKey) (int, map[string]any) {
		t.Helper()
		if r.Deployment == "" {
			r.Deployment = w.Deployment
		}
		if r.Nonce == "" {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			r.Nonce = hex.EncodeToString(b)
		}
		r.ExpiresAt = canon.Time(time.Now().Add(5 * time.Minute))
		sig, err := r.Sign(key)
		require.NoError(t, err)
		return callAs(t, "", "POST", "/api/authz/recovery", map[string]any{"request": r, "signature": sig})
	}
	state := func() map[string]any {
		code, st := call(t, w, kim, "GET", "/api/authz/admin-state", nil)
		require.Equal(t, 200, code, "%v", st)
		return st
	}
	generation := func() (g int64) {
		require.NoError(t, admin.QueryRow(ctx, "SELECT recovery_generation FROM "+itSchema+".authz_state").Scan(&g))
		return
	}
	adminHoldings := func(p string) []string {
		var ids []string
		rows, err := admin.Query(ctx, "SELECT id::text FROM "+itSchema+`.authz_record WHERE state = 'active'
			AND record_type = 'management_holding' AND body->>'holder' = $1 AND body->>'system_role' = 'authorization_admin'`, p)
		require.NoError(t, err)
		for rows.Next() {
			var id string
			require.NoError(t, rows.Scan(&id))
			ids = append(ids, id)
		}
		return ids
	}

	// only the recovery key's signature, for this deployment, once
	_, forged, _ := ed25519.GenerateKey(rand.Reader)
	code, out := recover(adminrecovery.RecoveryRequest{Action: "restore", Identity: sectest.Alice}, forged)
	require.Equal(t, 403, code, "%v", out)
	code, out = recover(adminrecovery.RecoveryRequest{Deployment: "another", Action: "restore", Identity: sectest.Alice}, recoveryPriv)
	require.Equal(t, 403, code, "%v", out)

	// restore Alice: a new generation, an admin holding of hers, operational again (CP15)
	before := generation()
	once := adminrecovery.RecoveryRequest{Action: "restore", Identity: sectest.Alice, Nonce: "restore-alice"}
	code, out = recover(once, recoveryPriv)
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "operational", out["admin_state"])
	assert.Equal(t, before+1, generation())
	require.Len(t, adminHoldings(sectest.Alice), 1)
	code, out = recover(once, recoveryPriv)
	require.Equal(t, 403, code, "a recovery request is used once: %v", out)

	// Alice compromised: replaced; the widening she asked for is cancelled; no admin is left (CP51)
	waitForView(t, w, sectest.Alice)
	asked := submitChange(t, w, sectest.Alice, unitReq("rc1", root, "asked", []sdkauthz.Segment{orderSeg(region("east"))},
		[]string{"demo.order.read"}), 202)
	alices := adminHoldings(sectest.Alice)[0]
	// a plan of hers still executing (written as it stands between two runs: an item pending): its pending items are
	// left for review (CP76)
	_, err := admin.Exec(ctx, "INSERT INTO "+itSchema+`.authz_plan (id, initiator, plan_key, draft_digest, plan_state)
		VALUES ('01900000-0000-7000-8000-00000000c076', $1, 'rc-plan', 'd', 'executing')`, sectest.Alice)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, "INSERT INTO "+itSchema+`.authz_plan_item (plan, item_key, position, request, item_state)
		VALUES ('01900000-0000-7000-8000-00000000c076', 'p', 0, '{}', 'pending')`)
	require.NoError(t, err)
	code, out = recover(adminrecovery.RecoveryRequest{Action: "replace", Holdings: []string{alices}}, recoveryPriv)
	require.Equal(t, 200, code, "%v", out)
	var itemNow string
	require.NoError(t, admin.QueryRow(ctx, "SELECT item_state FROM "+itSchema+".authz_plan_item WHERE item_key = 'p'"+
		" AND plan = '01900000-0000-7000-8000-00000000c076'").Scan(&itemNow))
	assert.Equal(t, plans.ItemNeedsReview, itemNow, "her plan's pending item is to be reviewed")
	assert.Equal(t, "recovery_pending", out["admin_state"])
	assert.Equal(t, "held", recordOf(t, admin, alices).State)
	assert.Equal(t, recordState{State: "ended", EndReason: "cancelled", Revision: 1, StateRev: 2}, withoutReason(recordOf(t, admin, asked["record"])))

	// Olga restored while her account is disabled: administrator recovery until it is active (CP74); abort goes back
	// (CP64); restored again, her holding is not made twice
	require.NoError(t, e.iam.set(ctx, olga, "disabled", 1))
	require.Eventually(t, func() bool {
		var n int
		_ = admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".authz_account_signal WHERE principal = $1", olga).Scan(&n)
		return n == 1
	}, 10*time.Second, 100*time.Millisecond, "her account applied")
	code, out = recover(adminrecovery.RecoveryRequest{Action: "restore", Identity: olga}, recoveryPriv)
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "admin_recovery", out["admin_state"])
	code, out = recover(adminrecovery.RecoveryRequest{Action: "abort"}, recoveryPriv)
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "recovery_pending", out["admin_state"])
	code, out = recover(adminrecovery.RecoveryRequest{Action: "restore", Identity: olga}, recoveryPriv)
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "admin_recovery", out["admin_state"])
	assert.Len(t, adminHoldings(olga), 1)
	require.NoError(t, e.iam.set(ctx, olga, "active", 2))
	require.Eventually(t, func() bool { return state()["state"] == "operational" }, 10*time.Second, 200*time.Millisecond,
		"her account active: operational")

	// the last admin's account disabled at the identity member: pending recovery again (CP26)
	require.NoError(t, e.iam.set(ctx, olga, "disabled", 3))
	require.Eventually(t, func() bool { return state()["state"] == "recovery_pending" }, 10*time.Second, 200*time.Millisecond,
		"no admin left")

	// Carol, frozen at the identity member since the identity phase: restoring her releases her identity-side
	// disposition and what it holds; her account still frozen, the recovery goes on (CP57)
	var carols string
	require.NoError(t, admin.QueryRow(ctx, "SELECT id::text FROM "+itSchema+`.authz_disposition WHERE subject = $1
		AND origin = 'identity_side' AND state = 'active'`, carol).Scan(&carols))
	var held string
	require.NoError(t, admin.QueryRow(ctx, "SELECT id::text FROM "+itSchema+".authz_record WHERE disposition = $1 LIMIT 1", carols).Scan(&held))
	code, out = recover(adminrecovery.RecoveryRequest{Action: "restore", Identity: carol}, recoveryPriv)
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "admin_recovery", out["admin_state"], "her account is still frozen")
	var st string
	require.NoError(t, admin.QueryRow(ctx, "SELECT state FROM "+itSchema+".authz_disposition WHERE id = $1", carols).Scan(&st))
	assert.Equal(t, "released", st)
	assert.Equal(t, "active", recordOf(t, admin, held).State)
}
