//go:build integration

package itest

import (
	"context"
	"testing"
	"time"

	core "github.com/brickKit/infra-authz/v3/internal/core"
	effectpoint "github.com/brickKit/infra-authz/v3/internal/effectpoint"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAccountStatusChanges is T9d (security 08, "管理员账号的状态变更"; A134), on a deployment of its own (it makes
// admins and changes their accounts, which the long story's later phases count): the identity member asks
// CheckAccountChange before a change; a confirmation binds the account, the status and the version; the account
// status carrying it uses it; an admin account re-enabled without a valid one has its holdings pending confirmation
// (CP42, CP47) until a protected reconfirmation.
func TestAccountStatusChanges(t *testing.T) {
	e := startE2E(t)
	w, ctx, admin := e.w, e.ctx, e.admin
	units := listRecords(t, w, sectest.Alice, "management_unit")
	require.Len(t, units, 1)
	root := units[0]["id"].(string)
	const una, quinn = "0190f3a1-0000-7000-8000-0000000000c5", "0190f3a1-0000-7000-8000-0000000000c6"
	versions := map[string]int64{}
	status := func(who, st, confirmation string) {
		t.Helper()
		versions[who]++
		require.NoError(t, e.iam.setConfirmed(ctx, who, st, confirmation, versions[who]))
		require.Eventually(t, func() bool {
			var got string
			_ = admin.QueryRow(ctx, "SELECT coalesce(data->>'security_version', '') FROM "+itSchema+
				".be_projection WHERE projection = 'accounts' AND record_id = $1", who).Scan(&got)
			return got == itoa64(versions[who])
		}, 10*time.Second, 100*time.Millisecond, "the member applied %s's status %s", who, st)
	}
	for _, p := range []string{sectest.Bob, una, quinn} {
		status(p, "active", "")
	}
	// Bob and Quinn manage records (the member's own operations), then hold the authorization admin role
	manager := []sdkauthz.Segment{}
	for _, op := range []string{core.OpRead, core.OpChange, core.OpTighten} {
		manager = append(manager, sdkauthz.Segment{ResourceType: core.Records, Operation: op, Atoms: map[string]sdkauthz.Atom{core.Holder: {Kind: "all"}},
			ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}})
	}
	for _, op := range []string{core.OpDispRead, core.OpRelease} { // Bob also confirms the release of a disposition
		manager = append(manager, sdkauthz.Segment{ResourceType: core.Dispositions, Operation: op, Atoms: map[string]sdkauthz.Atom{},
			ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}})
	}
	submitChange(t, w, sectest.Alice, grantReq("ac0", root, sectest.Bob, manager), 200)
	submitChange(t, w, sectest.Alice, grantReq("ac0q", root, quinn, manager), 200)
	protect(t, w, sectest.Alice, widenReq("ac1", "management_holding",
		map[string]any{"unit": root, "holder": sectest.Bob, "system_role": "authorization_admin"}))
	waitForView(t, w, sectest.Bob)
	protectBy(t, w, sectest.Alice, sectest.Bob, widenReq("ac2", "management_holding",
		map[string]any{"unit": root, "holder": quinn, "system_role": "authorization_admin"}))
	waitForView(t, w, quinn)
	asQuinn := func(path string, body map[string]any) (int, map[string]any) { // a token at Quinn's current version
		return callAs(t, "Bearer "+w.TokenAt(quinn, versions[quinn]), "POST", path, body)
	}

	accounts := authzv3.NewAccountServiceClient(dial(t, w, iamID))
	check := func(account, state, requester, confirmation string, second bool) *authzv3.CheckAccountChangeResponse {
		t.Helper()
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		out, err := accounts.CheckAccountChange(cctx, &authzv3.CheckAccountChangeRequest{Account: account, TargetState: state,
			SecurityVersion: versions[account], Requester: requester, Confirmation: confirmation, SecondPerson: second})
		require.NoError(t, err)
		return out
	}
	confirmAccount := func(who, account, state string) string {
		t.Helper()
		code, out := call(t, w, who, "POST", "/api/authz/confirmations", map[string]any{"account": account, "target_state": state})
		require.Equal(t, 201, code, "%v", out)
		return out["id"].(string)
	}
	const allowed, required, refused = authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_ALLOWED,
		authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_CONFIRMATION_REQUIRED, authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_REFUSED

	// a user's account: nothing needed; beyond T_tight the identity member's rule asks for a second person (CP80)
	out := check(una, "disabled", sectest.Alice, "", false)
	assert.Equal(t, allowed, out.GetVerdict())
	assert.False(t, out.GetAdministrator())
	assert.Equal(t, required, check(una, "disabled", sectest.Alice, "", true).GetVerdict())
	c1 := confirmAccount(sectest.Bob, una, "disabled")
	assert.Equal(t, allowed, check(una, "disabled", sectest.Alice, c1, true).GetVerdict())
	assert.Equal(t, refused, check(una, "disabled", sectest.Bob, c1, true).GetVerdict(), "the confirmer is the requester")
	assert.Equal(t, refused, check(una, "security_frozen", sectest.Alice, c1, true).GetVerdict(), "another status")
	late := confirmAccount(sectest.Bob, una, "disabled")
	_, err := admin.Exec(ctx, "UPDATE "+itSchema+".authz_confirmation SET expires_at = now() - interval '1 second' WHERE id = $1", late)
	require.NoError(t, err)
	assert.Equal(t, refused, check(una, "disabled", sectest.Alice, late, true).GetVerdict(), "expired")
	status(una, "disabled", c1) // the status carrying it uses it
	var used *string
	require.NoError(t, admin.QueryRow(ctx, "SELECT consumed_by_change FROM "+itSchema+".authz_confirmation WHERE id = $1", c1).Scan(&used))
	require.NotNil(t, used, "used when the account status carrying it was applied")
	assert.Equal(t, "account:"+una+"@2", *used)

	// an admin's account: protected, whoever asks; a confirmation by the account itself never counts (CP96)
	out = check(quinn, "disabled", sectest.Alice, "", false)
	assert.Equal(t, required, out.GetVerdict())
	assert.True(t, out.GetAdministrator())
	code, own := asQuinn("/api/authz/confirmations", map[string]any{"account": quinn, "target_state": "disabled"})
	assert.Equal(t, 403, code, "nobody confirms a change of their own account: %v", own)
	c2 := confirmAccount(sectest.Bob, quinn, "security_frozen")
	assert.Equal(t, allowed, check(quinn, "security_frozen", sectest.Alice, c2, false).GetVerdict())

	// the deployment owner stands in on a tightening of an admin's account at any time, on a re-enable only when no
	// other authorization admin is available (Bob is)
	ownerAccount := func(account, state string) string {
		t.Helper()
		code, p := call(t, w, sectest.Alice, "GET", "/api/authz/confirmations/owner-payload?account="+account+"&target_state="+state, nil)
		require.Equal(t, 200, code, "%v", p)
		str := func(k string) string { v, _ := p[k].(string); return v }
		o := sdkauthz.OwnerConfirmation{Deployment: str("deployment"), Target: str("target"), ExpectedRevision: str("expected_revision"),
			ExpiresAt: str("expires_at")}
		sig, err := o.Sign(ownerPriv)
		require.NoError(t, err)
		code, out := call(t, w, sectest.Alice, "POST", "/api/authz/confirmations", map[string]any{"account": account,
			"target_state": state, "basis": "deployment_owner", "expires_at": o.ExpiresAt, "signature": sig})
		require.Equal(t, 201, code, "%v", out)
		return out["id"].(string)
	}
	assert.Equal(t, allowed, check(quinn, "security_frozen", sectest.Alice, ownerAccount(quinn, "security_frozen"), false).GetVerdict(),
		"the owner on a tightening")
	assert.Equal(t, refused, check(quinn, "active", sectest.Alice, ownerAccount(quinn, "active"), false).GetVerdict(),
		"not on a re-enable while Bob is available")

	// frozen with Bob's confirmation (the holding is held by the identity-side disposition, not ended: a plain
	// disablement ends what the account is the source of, T4g), then unfrozen at the console with no confirmation:
	// the admin holding awaits a reconfirmation (CP42), unavailable
	status(quinn, "security_frozen", c2)
	status(quinn, "active", "")
	pending := func() bool {
		ok, err := pendingConfirmationAt(ctx, admin, quinn)
		require.NoError(t, err)
		return ok
	}
	assert.True(t, pending(), "confirmation_backfill_pending on the holding")
	// his identity-side disposition released (Bob confirms the protected release): the holding is active again, yet
	// awaiting a reconfirmation it does not qualify him as a confirmer
	var disp string
	var rev int64
	var refs []string
	require.NoError(t, admin.QueryRow(ctx, "SELECT id::text, revision, signal_ref FROM "+itSchema+
		".authz_disposition WHERE subject = $1 AND origin = 'identity_side' AND state = 'active'", quinn).Scan(&disp, &rev, &refs))
	code, rc := call(t, w, sectest.Bob, "POST", "/api/authz/confirmations", map[string]any{"disposition": disp,
		"expected_revision": map[string]any{"domain": effectpoint.DispositionDomain, "value": itoa64(rev)}})
	require.Equal(t, 201, code, "%v", rc)
	code, rel := call(t, w, sectest.Alice, "POST", "/api/authz/dispositions/"+disp+"/release", map[string]any{"change_key": "acr",
		"signal_refs": refs, "disposition_revision": map[string]any{"domain": effectpoint.DispositionDomain, "value": itoa64(rev)},
		"confirmation_ids": []any{rc["id"]}})
	require.Equal(t, 200, code, "%v", rel)
	var held int
	require.NoError(t, admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".authz_record WHERE record_type = 'management_holding'"+
		" AND body->>'holder' = $1 AND state = 'active'", quinn).Scan(&held))
	require.Equal(t, 1, held, "precondition: his admin holding is active again")
	assert.True(t, pending(), "still awaiting a reconfirmation")
	code, out2 := asQuinn("/api/authz/confirmations", map[string]any{"account": una, "target_state": "active"})
	assert.Equal(t, 403, code, "a holding pending confirmation does not qualify its holder as a confirmer: %v", out2)
	out = check(sectest.Bob, "active", sectest.Alice, ownerAccount(sectest.Bob, "active"), false)
	assert.Equal(t, allowed, out.GetVerdict(),
		"no other admin is available besides Alice and Bob (Quinn's holding awaits a reconfirmation): the owner stands in: %s", out.GetReason())

	// the protected reconfirmation: without a confirmation it waits; with Bob's it counts again
	code, out2 = call(t, w, sectest.Alice, "POST", "/api/authz/accounts/"+quinn+"/reconfirm", map[string]any{})
	require.Equal(t, 202, code, "%v", out2)
	assert.Equal(t, "CONFIRMATION_REQUIRED", out2["reason"])
	c3 := confirmAccount(sectest.Bob, quinn, "active")
	code, out2 = call(t, w, sectest.Alice, "POST", "/api/authz/accounts/"+quinn+"/reconfirm", map[string]any{"confirmation": c3})
	require.Equal(t, 204, code, "%v", out2)
	assert.False(t, pending(), "reconfirmed")

	// a re-enable carrying a confirmation of another account, or a used one, is no confirmation (CP47)
	status(quinn, "security_frozen", confirmAccount(sectest.Bob, quinn, "security_frozen"))
	status(quinn, "active", c1)
	assert.True(t, pending(), "a used confirmation of another account does not hold")
	// a re-enable with a valid confirmation clears it
	status(quinn, "security_frozen", confirmAccount(sectest.Bob, quinn, "security_frozen"))
	c5 := confirmAccount(sectest.Bob, quinn, "active")
	status(quinn, "active", c5)
	assert.False(t, pending(), "a re-enable with a valid confirmation")
}

// pendingConfirmationAt reads 09a's confirmation_backfill_pending on a principal's admin holdings.
func pendingConfirmationAt(ctx context.Context, admin *pgx.Conn, principal string) (bool, error) {
	var is bool
	err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM `+itSchema+`.authz_record WHERE state IN ('active', 'held')
		AND record_type = 'management_holding' AND body->>'holder' = $1 AND (body->>'confirmation_backfill_pending')::boolean)`,
		principal).Scan(&is)
	return is, err
}
