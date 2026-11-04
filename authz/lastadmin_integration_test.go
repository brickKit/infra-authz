//go:build integration

package authz

import (
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lastAdmin is T6d (security 08's last-admin invariant, rows 27-28): what counts is whether a person stays available
// once the change ends the holdings it ends — Alice's other admin holding keeps her one when she gives up the root's;
// ending the unit that holds the last admin holding is refused. It runs last: Alice no longer manages the root after.
func (e *e2e) lastAdmin() {
	t, w, admin, ctx, root := e.t, e.w, e.admin, e.ctx, e.root
	scope := []sdkauthz.Segment{orderSeg(region("east"))}
	ops := []string{"demo.order.read"}
	// Judy gives up her admin holding (Alice is still available), and a day passes (the cooling-off)
	var judys string
	require.NoError(t, admin.QueryRow(ctx, "SELECT id::text FROM "+itSchema+`.authz_record WHERE state = 'active'
		AND record_type = 'management_holding' AND body->>'holder' = $1`, judy).Scan(&judys))
	var code int
	var out map[string]any
	require.Eventually(t, func() bool {
		code, out = call(t, w, judy, "POST", "/api/authz/relinquishments", tightenReq("la0", judys))
		return code == 200
	}, 10*time.Second, 200*time.Millisecond, "%v", out)
	_, err := admin.Exec(ctx, "UPDATE "+itSchema+".authz_record SET updated_at = now() - interval '25 hours'"+
		" WHERE record_type = 'management_holding' AND state <> 'active'")
	require.NoError(t, err)

	// Alice holds a second admin holding in a unit of her own; Kim, who manages the root, may change and tighten records
	unit := protect(t, w, sectest.Alice, unitReq("la1", root, "last", scope, ops))
	protect(t, w, sectest.Alice, widenReq("la2", "management_holding",
		map[string]any{"unit": unit["record"], "holder": sectest.Alice, "system_role": "authorization_admin"}))
	segs := []sdkauthz.Segment{}
	for _, op := range []string{OpRead, OpChange, OpTighten} {
		segs = append(segs, sdkauthz.Segment{ResourceType: Records, Operation: op, Atoms: map[string]sdkauthz.Atom{Holder: {Kind: "all"}},
			ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}})
	}
	submitChange(t, w, sectest.Alice, grantReq("la3", root, kim, segs), 200)
	waitForView(t, w, kim)

	// she gives up the root's admin holding: her other one keeps her available
	var roots string
	require.NoError(t, admin.QueryRow(ctx, "SELECT id::text FROM "+itSchema+`.authz_record WHERE state = 'active'
		AND record_type = 'management_holding' AND body->>'holder' = $1 AND body->>'unit' = $2`, sectest.Alice, root).Scan(&roots))
	submitChange(t, w, sectest.Alice, tightenReq("la4", roots), 200)

	// ending her unit would end the last admin holding: refused (row 27)
	code, out = call(t, w, kim, "POST", "/api/authz/tightenings", tightenReq("la5", unit["record"]))
	require.Equal(t, 409, code, "%v", out)
	assert.Equal(t, "LAST_ADMIN_PROTECTED", out["reason"])
	assert.Equal(t, "active", recordOf(t, admin, unit["record"]).State)
}
