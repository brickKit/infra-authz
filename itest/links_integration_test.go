//go:build integration

package itest

import (
	"context"
	"testing"
	"time"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestAccountLinks is C1's E4c (security 08 row 21 and "确认与受保护操作": the link of an account to an employee and
// its end are protected operations), on a deployment with the stand-in employee member: a confirmation binds the
// employee, the account, the action and the employee's version; the employee member asks CheckLinkChange before the
// change and nothing is used then; the link record carrying it uses it when this member applies it, once. A link is a
// widening (the owner stands in only when no other admin is available), its end a tightening (the owner stands in).
// Administrators answers which accounts hold the admin role; both methods answer the employee member only.
func TestAccountLinks(t *testing.T) {
	e := startE2E(t, withEmployee)
	w, ctx, admin, emp := e.w, e.ctx, e.admin, e.emp
	units := listRecords(t, w, sectest.Alice, "management_unit")
	require.Len(t, units, 1)
	root := units[0]["id"].(string)
	const una = "0190f3a1-0000-7000-8000-0000000000d1"
	require.NoError(t, e.iam.set(ctx, una, "active", 1))
	// Bob manages records and holds the authorization admin role: Alice's independent confirmer
	manager := []sdkauthz.Segment{}
	for _, op := range []string{core.OpRead, core.OpChange, core.OpTighten} {
		manager = append(manager, sdkauthz.Segment{ResourceType: core.Records, Operation: op, Atoms: map[string]sdkauthz.Atom{core.Holder: {Kind: "all"}},
			ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}})
	}
	submitChange(t, w, sectest.Alice, grantReq("lk0", root, sectest.Bob, manager), 200)
	protect(t, w, sectest.Alice, widenReq("lk1", "management_holding",
		map[string]any{"unit": root, "holder": sectest.Bob, "system_role": "authorization_admin"}))
	waitForView(t, w, sectest.Bob)

	ann := ids.New().String()
	require.NoError(t, emp.hire(ctx, ann, "active", 1))
	links := authzv3.NewAccountServiceClient(dial(t, w, empID))
	check := func(account, action, requester, confirmation string, version int64) authzv3.AccountChangeVerdict {
		t.Helper()
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		out, err := links.CheckLinkChange(cctx, &authzv3.CheckLinkChangeRequest{Employee: ann, Account: account, Action: action,
			EmployeeVersion: version, Requester: requester, Confirmation: confirmation})
		require.NoError(t, err)
		return out.GetVerdict()
	}
	confirm := func(who, account, action string, version int64) (int, map[string]any) {
		return call(t, w, who, "POST", "/api/authz/confirmations", map[string]any{"employee": ann, "account": account,
			"action": action, "employee_version": version})
	}
	const allowed, required, refused = authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_ALLOWED,
		authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_CONFIRMATION_REQUIRED, authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_REFUSED

	// none given: required; one by another admin binds the employee, the account, the action and the version
	assert.Equal(t, required, check(una, "link", sectest.Alice, "", 1))
	code, c1 := confirm(sectest.Bob, una, "link", 1)
	require.Equal(t, 201, code, "%v", c1)
	conf := c1["id"].(string)
	assert.Equal(t, allowed, check(una, "link", sectest.Alice, conf, 1))
	assert.Equal(t, allowed, check(una, "link", sectest.Alice, conf, 1), "checking uses nothing")
	assert.Equal(t, refused, check(una, "link", sectest.Bob, conf, 1), "the confirmer is the requester")
	assert.Equal(t, refused, check(una, "link", sectest.Alice, conf, 2), "another version of the employee")
	assert.Equal(t, refused, check(una, "unlink", sectest.Alice, conf, 1), "another action")
	assert.Equal(t, refused, check(carol, "link", sectest.Alice, conf, 1), "another account")
	code, own := confirm(sectest.Bob, sectest.Bob, "link", 1)
	assert.Equal(t, 403, code, "nobody confirms a link of their own account: %v", own)
	// Carol manages records but holds no admin role (Una, with no grant at all, does not see the route: 404)
	submitChange(t, w, sectest.Alice, grantReq("lk2", root, carol, manager), 200)
	waitForView(t, w, carol)
	code, plain := confirm(carol, una, "link", 1)
	assert.Equal(t, 403, code, "only an authorization admin confirms: %v", plain)
	late := func() string {
		_, c := confirm(sectest.Bob, una, "link", 1)
		_, err := admin.Exec(ctx, "UPDATE "+itSchema+".authz_confirmation SET expires_at = now() - interval '1 second' WHERE id = $1", c["id"])
		require.NoError(t, err)
		return c["id"].(string)
	}()
	assert.Equal(t, refused, check(una, "link", sectest.Alice, late, 1), "expired")

	// the owner: on a link only when no other admin is available (Bob is); on the end of one at any time
	owner := func(account, action string, version int64) string {
		t.Helper()
		code, p := call(t, w, sectest.Alice, "GET", "/api/authz/confirmations/owner-payload?employee="+ann+"&account="+account+
			"&action="+action+"&employee_version="+itoa64(version), nil)
		require.Equal(t, 200, code, "%v", p)
		str := func(k string) string { v, _ := p[k].(string); return v }
		o := sdkauthz.OwnerConfirmation{Deployment: str("deployment"), Target: str("target"), ExpectedRevision: str("expected_revision"),
			ExpiresAt: str("expires_at")}
		sig, err := o.Sign(ownerPriv)
		require.NoError(t, err)
		code, out := call(t, w, sectest.Alice, "POST", "/api/authz/confirmations", map[string]any{"employee": ann, "account": account,
			"action": action, "employee_version": version, "basis": "deployment_owner", "expires_at": o.ExpiresAt, "signature": sig})
		require.Equal(t, 201, code, "%v", out)
		return out["id"].(string)
	}
	assert.Equal(t, refused, check(una, "link", sectest.Alice, owner(una, "link", 1), 1), "not on a link while Bob is available")
	assert.Equal(t, allowed, check(una, "unlink", sectest.Alice, owner(una, "unlink", 1), 1), "the owner on the end of a link")

	// the link carrying it uses it when applied, once
	l1 := ids.New().String()
	require.NoError(t, emp.link(ctx, l1, ann, una, "active", conf, nil, 1))
	used := func(id string) string {
		var by *string
		require.NoError(t, admin.QueryRow(ctx, "SELECT consumed_by_change FROM "+itSchema+".authz_confirmation WHERE id = $1", id).Scan(&by))
		if by == nil {
			return ""
		}
		return *by
	}
	require.Eventually(t, func() bool { return used(conf) != "" }, 15*time.Second, 100*time.Millisecond, "used when the link is applied")
	assert.Equal(t, "link:"+l1+"@1", used(conf))
	assert.Equal(t, refused, check(una, "link", sectest.Alice, conf, 1), "used")

	// its end: a confirmation of the unlink, used by the ended link
	code, c2 := confirm(sectest.Bob, una, "unlink", 1)
	require.Equal(t, 201, code, "%v", c2)
	end := c2["id"].(string)
	assert.Equal(t, allowed, check(una, "unlink", sectest.Alice, end, 1))
	require.NoError(t, emp.link(ctx, l1, ann, una, "ended", conf, &end, 2))
	require.Eventually(t, func() bool { return used(end) != "" }, 15*time.Second, 100*time.Millisecond)
	assert.Equal(t, "unlink:"+l1+"@2", used(end))

	// the admins among the accounts asked
	got, err := links.Administrators(ctx, &authzv3.AdministratorsRequest{Accounts: []string{sectest.Bob, una, sectest.Alice}})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{sectest.Alice, sectest.Bob}, got.GetAdministrators())
	_, err = links.Administrators(ctx, &authzv3.AdministratorsRequest{Accounts: make([]string, 101)})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "at most 100")
	// the employee member only
	_, err = authzv3.NewAccountServiceClient(dial(t, w, iamID)).Administrators(ctx, &authzv3.AdministratorsRequest{Accounts: []string{una}})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = authzv3.NewAccountServiceClient(dial(t, w, iamID)).CheckLinkChange(ctx, &authzv3.CheckLinkChangeRequest{Employee: ann})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}
