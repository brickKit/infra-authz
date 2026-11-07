//go:build integration

package itest

import (
	"strconv"
	"testing"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testRelinquish is D82: anyone may relinquish their own grant (security 08, "变更方向"); the member's own view gives
// every holder a fixed segment of infra.authz.security_record.relinquish, nobody grants it. It ends only the
// requester's own records, through the effect point.
func testRelinquish(t *testing.T, w *sectest.World, admin *pgx.Conn, root string) {
	seg := []sdkauthz.Segment{orderSeg(region("east"))}
	mine := submitChange(t, w, sectest.Alice, grantReq("rl1", root, carol, seg), 200)
	kept := submitChange(t, w, sectest.Alice, grantReq("rl2", root, carol, seg), 200) // she still holds one after
	others := submitChange(t, w, sectest.Alice, grantReq("rl3", root, dave, seg), 200)
	code, out := call(t, w, carol, "POST", "/api/authz/tightenings", tightenReq("rl4", mine["record"]))
	require.Contains(t, []int{403, 404}, code, "the precondition: carol may not tighten security records (%v)", out)

	n := 0
	relinquish := func(target any) (int, map[string]any) { // a new key each try: admission's refusal binds nothing
		n++
		return call(t, w, carol, "POST", "/api/authz/relinquishments", tightenReq("rl-"+strconv.Itoa(n), target))
	}
	// her grant reaches the member's own view, with it the fixed segment (the member verifies its own view every 2.5 s)
	require.Eventually(t, func() bool { code, _ := relinquish(mine["record"]); return code == 200 }, 10*time.Second,
		200*time.Millisecond, "carol relinquishes her own grant")
	assert.Equal(t, recordState{State: "ended", EndReason: "relinquished", Revision: 1, StateRev: 2}, recordOf(t, admin, mine["record"]))
	// someone else's: not hers to see (holder = self), so not found; nothing changes
	code, out = relinquish(others["record"])
	require.Equal(t, 404, code, "%v", out)
	assert.Equal(t, "active", recordOf(t, admin, others["record"]).State)
	// what she sees of the security records: her own only
	code, out = call(t, w, carol, "GET", "/api/authz/records?type=grant", nil)
	require.Equal(t, 200, code, "%v", out)
	var seen []any
	for _, r := range out["records"].([]any) {
		seen = append(seen, r.(map[string]any)["id"])
	}
	assert.Equal(t, []any{kept["record"]}, seen, "her one remaining grant, not dave's")
	// only whole records: a narrowing or a termination is not a relinquishment
	narrow := tightenReq("rl-narrow", kept["record"])
	narrow["termination"] = "withdraw"
	narrow["expected_state_revision"] = map[string]any{"domain": "authz.record.state", "value": "1"}
	code, out = call(t, w, carol, "POST", "/api/authz/relinquishments", narrow)
	require.Equal(t, 400, code, "%v", out)
	assert.Contains(t, out["detail"], "a relinquishment ends one whole record")
	submitChange(t, w, sectest.Alice, tightenReq("rl5", kept["record"]), 200)
	submitChange(t, w, sectest.Alice, tightenReq("rl6", others["record"]), 200)
}
