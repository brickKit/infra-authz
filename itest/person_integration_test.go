//go:build integration

package itest

import (
	"slices"
	"testing"
	"time"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOnePerson is C1's E4d (security 08: "独立指不同的自然人：关联到同一员工的多个账号算一个人"; the disposition's
// "账号集合"), on a deployment with the stand-in employee member: two accounts linked to one employee are one person,
// so neither confirms what the other asks, nor a link of their own employee; a disposition covers the person's
// accounts, an account linked to its employee afterwards too.
func TestOnePerson(t *testing.T) {
	e := startE2E(t, withEmployee)
	e.definitionsAndViews()
	w, ctx, admin, emp := e.w, e.ctx, e.admin, e.emp
	units := listRecords(t, w, sectest.Alice, "management_unit")
	require.Len(t, units, 1)
	root := units[0]["id"].(string)
	const bob2, una, carol2, carol3 = "0190f3a1-0000-7000-8000-0000000000f1", "0190f3a1-0000-7000-8000-0000000000f2",
		"0190f3a1-0000-7000-8000-0000000000f3", "0190f3a1-0000-7000-8000-0000000000f4"
	for _, p := range []string{bob2, una, carol2, carol3} {
		require.NoError(t, e.iam.set(ctx, p, "active", 1))
	}
	// Bob and his second account both manage records and hold the authorization admin role
	manager := []sdkauthz.Segment{}
	for _, op := range []string{core.OpRead, core.OpChange, core.OpTighten} {
		manager = append(manager, sdkauthz.Segment{ResourceType: core.Records, Operation: op, Atoms: map[string]sdkauthz.Atom{core.Holder: {Kind: "all"}},
			ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}})
	}
	for i, p := range []string{sectest.Bob, bob2} {
		submitChange(t, w, sectest.Alice, grantReq("op0"+itoa64(int64(i)), root, p, manager), 200)
		req := widenReq("op1"+itoa64(int64(i)), "management_holding", map[string]any{"unit": root, "holder": p, "system_role": "authorization_admin"})
		if i == 0 {
			protect(t, w, sectest.Alice, req) // the owner stands in: no other admin yet
		} else {
			protectBy(t, w, sectest.Alice, sectest.Bob, req) // Bob is available now: he confirms
		}
		waitForView(t, w, p)
	}
	// Ben is one employee with both accounts
	ben, l1, l2 := ids.New().String(), ids.New().String(), ids.New().String()
	require.NoError(t, emp.hire(ctx, ben, "active", 1))
	require.NoError(t, emp.link(ctx, l1, ben, sectest.Bob, "active", ids.New().String(), nil, 1))
	require.NoError(t, emp.link(ctx, l2, ben, bob2, "active", ids.New().String(), nil, 1))
	require.Eventually(t, func() bool { return factOf(t, admin, l1).Version == 1 && factOf(t, admin, l2).Version == 1 },
		15*time.Second, 100*time.Millisecond, "both links applied")

	// an account's status change Bob asks for: his second account's confirmation is his own
	code, c := call(t, w, bob2, "POST", "/api/authz/confirmations", map[string]any{"account": una, "target_state": "disabled"})
	require.Equal(t, 201, code, "%v", c)
	accounts := authzv3.NewAccountServiceClient(dial(t, w, iamID))
	ask := func(requester string) authzv3.AccountChangeVerdict {
		out, err := accounts.CheckAccountChange(ctx, &authzv3.CheckAccountChangeRequest{Account: una, TargetState: "disabled",
			SecurityVersion: 1, Requester: requester, Confirmation: c["id"].(string), SecondPerson: true})
		require.NoError(t, err)
		return out.GetVerdict()
	}
	assert.Equal(t, authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_REFUSED, ask(sectest.Bob), "one person")
	assert.Equal(t, authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_ALLOWED, ask(sectest.Alice), "another person")
	// nor does it confirm a link of Ben's, whatever the account
	code, own := call(t, w, bob2, "POST", "/api/authz/confirmations", map[string]any{"employee": ben, "account": una,
		"action": "link", "employee_version": 1})
	assert.Equal(t, 403, code, "a link of one's own employee: %v", own)
	// a protected widening Bob asks for (an admin holding for Una): his second account's confirmation does not hold, the
	// record waits; Alice's does
	asked := submitChange(t, w, sectest.Bob, widenReq("op5", "management_holding",
		map[string]any{"unit": root, "holder": una, "system_role": "authorization_admin"}), 202)
	require.Equal(t, "awaiting_confirmation", asked["outcome"], "%v", asked)
	code, mine := call(t, w, bob2, "POST", "/api/authz/confirmations", map[string]any{"target": asked["record"]})
	require.Equal(t, 201, code, "%v", mine)
	require.Eventually(t, func() bool { return dueItemOf(t, admin, asked["record"]).State == "done" }, 10*time.Second,
		100*time.Millisecond, "the confirmation's job has run")
	assert.Equal(t, "awaiting_confirmation", recordOf(t, admin, asked["record"]).State, "his own person's confirmation")
	code, alices := call(t, w, sectest.Alice, "POST", "/api/authz/confirmations", map[string]any{"target": asked["record"]})
	require.Equal(t, 201, code, "%v", alices)
	require.Eventually(t, func() bool { return recordOf(t, admin, asked["record"]).State == "active" }, 10*time.Second,
		100*time.Millisecond, "another person's")

	// a confirmation by the other account counts once one of the links has ended (Bob's: the confirmer's own is active,
	// so only the other side of the person tells)
	require.NoError(t, emp.link(ctx, l1, ben, sectest.Bob, "ended", "", nil, 2))
	require.Eventually(t, func() bool { return factOf(t, admin, l1).State == "ended" }, 15*time.Second, 100*time.Millisecond)
	assert.Equal(t, authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_ALLOWED, ask(sectest.Bob), "two people again")

	// a disposition of Carol covers her person: an account linked to her employee before it, and one linked after
	regions := func(p string) []string {
		var out []string
		for _, s := range e.segmentsOf(p) {
			if s.ResourceType == "demo.order" {
				out = append(out, s.Atoms["region"].Values...)
			}
		}
		slices.Sort(out)
		return out
	}
	cid := ids.New().String()
	require.NoError(t, emp.hire(ctx, cid, "active", 1))
	lc, lc2 := ids.New().String(), ids.New().String()
	require.NoError(t, emp.link(ctx, lc, cid, carol, "active", ids.New().String(), nil, 1))
	require.NoError(t, emp.link(ctx, lc2, cid, carol2, "active", ids.New().String(), nil, 1))
	require.Eventually(t, func() bool { return factOf(t, admin, lc2).Version == 1 }, 15*time.Second, 100*time.Millisecond)
	for i, p := range []string{carol2, carol3} {
		submitChange(t, w, sectest.Alice, grantReq("op2"+itoa64(int64(i)), root, p, []sdkauthz.Segment{orderSeg(region("east"))}), 200)
		submitChange(t, w, sectest.Alice, grantReq("op3"+itoa64(int64(i)), root, p, []sdkauthz.Segment{orderSeg(region("west"))}), 200)
	}
	require.Eventually(t, func() bool { return len(regions(carol2)) == 2 && len(regions(carol3)) == 2 }, 10*time.Second,
		200*time.Millisecond, "the precondition")
	code, out := call(t, w, sectest.Alice, "POST", "/api/authz/dispositions", map[string]any{"change_key": "op4", "subject": carol,
		"suspended_segments": []sdkauthz.Segment{orderSeg(region("east"))}})
	require.Equal(t, 200, code, "%v", out)
	var recorded []string
	require.NoError(t, admin.QueryRow(ctx, "SELECT accounts FROM "+itSchema+".authz_disposition WHERE id = $1", out["record"]).Scan(&recorded))
	assert.ElementsMatch(t, []string{carol, carol2}, recorded, "her person's accounts then")
	assert.Equal(t, []string{"west"}, regions(carol2), "an account of hers when she was disposed")
	assert.Equal(t, []string{"east", "west"}, regions(carol3), "not hers yet")
	lc3 := ids.New().String()
	require.NoError(t, emp.link(ctx, lc3, cid, carol3, "active", ids.New().String(), nil, 1))
	require.Eventually(t, func() bool { return slices.Equal(regions(carol3), []string{"west"}) }, 15*time.Second,
		200*time.Millisecond, "an account linked to her employee afterwards does not escape it")
}
