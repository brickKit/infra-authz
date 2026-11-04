//go:build integration

package authz

import (
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Pia uses orders but manages nothing; Rex manages a unit that may only revoke.
const (
	pia = "0190f3a1-0000-7000-8000-0000000000a7"
	rex = "0190f3a1-0000-7000-8000-0000000000a8"
)

// handover is T7c (security 04's management actions, role templates and versions, an administrator stepping down):
// using is not managing and managing is not using (AM01); a role's new revision does not change its bindings, a
// rebinding is a new grant superseding the old one and proven like any (AM05, AM09); a manager who may revoke but not
// grant revokes within the unit, not elsewhere (AM07); a manager who steps down leaves the unit and its grants as
// they are, managed from above (AM14). It runs after the delegation phase and uses its units: Noah holds dl-top, Otto
// dl-child below it.
func (e *e2e) handover() {
	t, w, admin, ctx, root := e.t, e.w, e.admin, e.ctx, e.root
	top, child := unitNamed(t, admin, "dl-top"), unitNamed(t, admin, "dl-child")
	ops := []string{"demo.order.read"}
	mgr := []sdkauthz.Segment{}
	for _, op := range []string{OpRead, OpChange, OpTighten} {
		mgr = append(mgr, sdkauthz.Segment{ResourceType: Records, Operation: op, Atoms: map[string]sdkauthz.Atom{Holder: {Kind: "all"}},
			ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}})
	}
	for _, p := range []string{pia, rex} {
		require.NoError(t, e.iam.set(ctx, p, "active", 1))
		submitChange(t, w, sectest.Alice, grantReq("ho-m-"+p, root, p, mgr), 200)
	}
	denied := func(who string, req map[string]any) {
		t.Helper()
		out := submitChange(t, w, who, req, 403)
		require.Equal(t, "PERMISSION_DENIED", out["reason"], "%v", out)
	}

	// AM01: Pia reads orders and may call the change route, but holds no unit: she grants nothing; Noah manages
	// dl-top without reading a single order
	submitChange(t, w, sectest.Alice, grantReq("ho1", root, pia, []sdkauthz.Segment{orderSeg(region("east"))}), 200)
	waitForView(t, w, pia)
	denied(pia, grantReq("ho2", root, carol, []sdkauthz.Segment{orderSeg(region("east"))}))
	assert.NotEmpty(t, e.segmentsOf(pia), "she uses orders")
	assert.Empty(t, e.segmentsOf(noah), "he manages, and reads no order")

	// AM07: Rex's unit may only revoke: he revokes a wide grant in it, which he could not grant again, and nothing
	// governed elsewhere
	rv := protectBy(t, w, sectest.Alice, judy, widenReq("ho3", "management_unit", map[string]any{"parent": root, "name": "ho-revoke",
		"managed_scope": []sdkauthz.Segment{orderSeg(region("east", "west"))}, "grantable_operations": ops,
		"management_actions": []string{ActRevoke}, "max_subdelegation_depth": 0}))["record"]
	protectBy(t, w, sectest.Alice, judy, holdingReq("ho4", rv, rex))
	waitForView(t, w, rex)
	wide := submitChange(t, w, sectest.Alice, grantReq("ho5", rv, carol, []sdkauthz.Segment{orderSeg(region("east", "west"))}), 200)
	denied(rex, grantReq("ho6", rv, carol, []sdkauthz.Segment{orderSeg(region("east", "west"))}))
	elsewhere := submitChange(t, w, sectest.Alice, grantReq("ho7", top, carol, []sdkauthz.Segment{orderSeg(region("east"))}), 200)
	denied(rex, tightenReq("ho8", elsewhere["record"]))
	submitChange(t, w, rex, tightenReq("ho9", wide["record"]), 200)
	assert.Equal(t, "revoked", recordOf(t, admin, wide["record"]).EndReason)

	// AM05, AM09: a role's new revision is a new record; the grants bound to the old one keep its segments; a
	// rebinding supersedes the old grant and must contain it; editing roles stays an admin's
	role := func(key, name string, regions ...string) any {
		return submitChange(t, w, sectest.Alice, widenReq(key, "role_revision", map[string]any{"name": name,
			"segments_template": []sdkauthz.Segment{orderSeg(region(regions...))}}), 200)["record"]
	}
	v1 := role("ho10", "ho clerk", "north")
	bound := submitChange(t, w, sectest.Alice, widenReq("ho11", "grant", map[string]any{"governance_unit": root, "grantee": pia,
		"role_revision": v1}), 200)["record"]
	v2 := role("ho12", "ho clerk", "north", "south")
	assert.Equal(t, [][]string{{"east"}, {"north"}}, regionsOf(e.segmentsOf(pia)), "v2 changes no binding")
	narrower := role("ho13", "ho clerk", "south")
	out := submitChange(t, w, sectest.Alice, widenReq("ho14", "grant", map[string]any{"governance_unit": root, "grantee": pia,
		"role_revision": narrower, "predecessor": bound}), 403)
	assert.Equal(t, "CONTAINMENT_NOT_PROVEN", out["reason"], "a rebinding that does not contain the old grant: %v", out)
	submitChange(t, w, sectest.Alice, widenReq("ho15", "grant", map[string]any{"governance_unit": root, "grantee": pia,
		"role_revision": v2, "predecessor": bound}), 200)
	assert.Equal(t, "superseded", recordOf(t, admin, bound).EndReason)
	assert.Equal(t, [][]string{{"east"}, {"north", "south"}}, regionsOf(e.segmentsOf(pia)), "rebound to v2")
	denied(noah, widenReq("ho16", "role_revision", map[string]any{"name": "noah's", "segments_template": []sdkauthz.Segment{orderSeg(region("east"))}}))

	// AM14: Noah steps down; the unit, the unit below it and Otto's grant there stay; Otto still grants within it,
	// and the root's manager takes care of what Noah did
	var held string
	require.NoError(t, admin.QueryRow(ctx, "SELECT id::text FROM "+itSchema+`.authz_record WHERE state = 'active'
		AND record_type = 'management_holding' AND body->>'holder' = $1 AND body->>'unit' = $2`, noah, top).Scan(&held))
	var ottos string
	require.NoError(t, admin.QueryRow(ctx, "SELECT id::text FROM "+itSchema+`.authz_record WHERE state = 'active'
		AND record_type = 'grant' AND body->>'governance_unit' = $1 AND body->>'issued_by' = $2`, child, otto).Scan(&ottos))
	code, rel := call(t, w, noah, "POST", "/api/authz/relinquishments", tightenReq("ho17", held))
	require.Equal(t, 200, code, "%v", rel)
	assert.Equal(t, "relinquished", recordOf(t, admin, held).EndReason)
	for _, id := range []string{top, child, ottos} {
		assert.Equal(t, "active", recordOf(t, admin, id).State, "%s stays", id)
	}
	require.Eventually(t, func() bool {
		code, _ := call(t, w, noah, "POST", "/api/authz/changes", grantReq("ho18", child, carol, []sdkauthz.Segment{orderSeg(region("north"))}))
		return code == 403
	}, 10*time.Second, 200*time.Millisecond, "Noah no longer manages")
	submitChange(t, w, otto, grantReq("ho19", child, carol, []sdkauthz.Segment{orderSeg(region("north"))}), 200)
	submitChange(t, w, sectest.Alice, tightenReq("ho20", ottos), 200)
}
