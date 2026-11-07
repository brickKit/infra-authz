//go:build integration

package itest

import (
	"context"
	"testing"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unitNamed is the active management unit of that name.
func unitNamed(t *testing.T, admin *pgx.Conn, name string) string {
	var id string
	require.NoError(t, admin.QueryRow(context.Background(), "SELECT id::text FROM "+itSchema+`.authz_record
		WHERE state = 'active' AND record_type = 'management_unit' AND body->>'name' = $1`, name).Scan(&id))
	return id
}

// pending is T6e (security 08's pending recovery): Alice, the last authorization admin, disposes herself; with
// provably no admin available the deployment awaits an administrator recovery, the holding's cause recorded (CP14);
// meanwhile widenings of the management structure are refused, an ordinary grant and a tightening go on (CP49). It
// runs after the last-admin phase.
func (e *e2e) pending() {
	t, w, admin, root := e.t, e.w, e.admin, e.root
	last := unitNamed(t, admin, "last")
	var hers string
	require.NoError(t, admin.QueryRow(e.ctx, "SELECT id::text FROM "+itSchema+`.authz_record WHERE state = 'active'
		AND record_type = 'management_holding' AND body->>'holder' = $1 AND body->>'system_role' = 'authorization_admin'`,
		sectest.Alice).Scan(&hers)) // her admin holding: she holds plain ones too
	code, out := call(t, w, sectest.Alice, "POST", "/api/authz/dispositions", map[string]any{"change_key": "pe1",
		"subject": sectest.Alice, "domain": last, "suspended_segments": []sdkauthz.Segment{orderSeg(region("east"))}})
	require.Equal(t, 200, code, "a disposition is never held back by the last admin: %v", out)

	code, st := call(t, w, kim, "GET", "/api/authz/admin-state", nil)
	require.Equal(t, 200, code, "%v", st)
	assert.Equal(t, "recovery_pending", st["state"])
	assert.Equal(t, []any{map[string]any{"holding": hers, "cause": "security_disposition"}}, st["unavailable_holdings"])

	ops := []string{"demo.order.read"}
	code, out = call(t, w, kim, "POST", "/api/authz/changes", unitReq("pe2", root, "while-pending", []sdkauthz.Segment{orderSeg(region("east"))}, ops))
	require.NotEqual(t, 202, code, "%v", out)
	assert.Equal(t, "RECOVERY_IN_PROGRESS", out["reason"], "a widening of the management structure (row 13)")
	g := submitChange(t, w, kim, grantReq("pe3", root, grace, []sdkauthz.Segment{orderSeg(region("west"))}), 200)
	submitChange(t, w, kim, tightenReq("pe4", g["record"]), 200)
}
