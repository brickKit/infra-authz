//go:build integration

package itest

import (
	"testing"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nobody holds no grant or holding of any kind in any step.
const nobody = "0190f3a1-0000-7000-8000-0000000000f6"

// testOwnOperations is A177: GET /api/authz/me/operations answers the operation keys the caller holds now, computed
// as the views are (a revoked grant's keys go with it); one with no grant at all holds nothing, and nobody grants
// the read itself: every holder has a fixed segment of it, as of relinquish (D82).
func testOwnOperations(t *testing.T, w *sectest.World, root string) {
	own := func(who string) []any {
		code, out := call(t, w, who, "GET", "/api/authz/me/operations", nil)
		require.Equal(t, 200, code, "%v", out)
		ops, ok := out["operations"].([]any)
		require.True(t, ok, "operations is a list: %v", out)
		require.Equal(t, who, out["principal"], "the answer names the caller")
		return ops
	}
	assert.Empty(t, own(nobody), "no grant, no holding: nothing")

	g := submitChange(t, w, sectest.Alice, grantReq("own1", root, eve, []sdkauthz.Segment{orderSeg(region("north"))}), 200)
	require.Eventually(t, func() bool { return len(own(eve)) > 0 }, 10*time.Second, 200*time.Millisecond,
		"eve's grant reaches his own operations (the member verifies its own view every 2.5 s)")
	ops := own(eve)
	assert.Contains(t, ops, "demo.order.read", "another component's key she was granted")
	assert.Contains(t, ops, "infra.authz.security_record.own_operations", "the fixed segment of a holder")
	assert.Contains(t, ops, "infra.authz.security_record.relinquish")
	assert.NotContains(t, ops, "infra.authz.security_record.change", "not granted to her")
	for i := 1; i < len(ops); i++ {
		assert.Less(t, ops[i-1].(string), ops[i].(string), "sorted, each once")
	}

	submitChange(t, w, sectest.Alice, tightenReq("own2", g["record"]), 200)
	assert.NotContains(t, own(eve), "demo.order.read", "the revoked grant's keys are gone at once")
}
