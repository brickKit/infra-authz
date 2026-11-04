//go:build integration

package authz

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testUncomputable is a record whose intersection cannot be computed (security 08, "有效段的计算": held,
// uncomputable, until it can be) and its restore (restore_uncomputable through the effect point under a derived key;
// rows 25 and 30; CP103, CP115). Well-formed requests never make one (every pair the effect point accepts is in the
// table), so the test writes an atom of another kind into a grant in the table, and repairs it the same way.
func testUncomputable(t *testing.T, w *sectest.World, admin *pgx.Conn, root string, segmentsOf func(string) []sdkauthz.Segment) {
	ctx := context.Background()
	ops := []string{"demo.order.read"}
	require.Empty(t, segmentsOf(carol), "the precondition: carol holds no grant")
	setRegion := func(id any, atom string) {
		_, err := admin.Exec(ctx, "UPDATE "+itSchema+".authz_record SET body = jsonb_set(body, '{segments,0,atoms,region}', $2::jsonb) WHERE id = $1",
			id, atom)
		require.NoError(t, err)
	}
	narrowUnit := func(key string, unit any, name string, regions ...string) {
		raw, _ := json.Marshal(map[string]any{"name": name, "parent": root, "managed_scope": []sdkauthz.Segment{orderSeg(region(regions...))},
			"grantable_operations": ops})
		submitChange(t, w, sectest.Alice, map[string]any{"change_key": key, "direction": "tighten", "target": unit,
			"candidate": json.RawMessage(raw), "candidate_digest": candidateDigest("management_unit", raw)}, 200)
	}
	state := func(id any) (string, string) {
		var st string
		var hold *string
		require.NoError(t, admin.QueryRow(ctx, "SELECT state, hold_reason FROM "+itSchema+".authz_record WHERE id = $1", id).Scan(&st, &hold))
		if hold == nil {
			return st, ""
		}
		return st, *hold
	}
	const tree, eastWest = `{"kind":"tree","items":[{"path":"/east","mode":"subtree"}]}`, `{"kind":"in","values":["east","west"]}`

	// the closure finds it cannot be computed: held (uncomputable), no access
	u1 := submitChange(t, w, sectest.Alice, unitReq("uc1", root, "uc-one", []sdkauthz.Segment{orderSeg(region("east", "west", "north"))}, ops), 200)
	g := submitChange(t, w, sectest.Alice, grantReq("uc2", u1["record"], carol, []sdkauthz.Segment{orderSeg(region("east", "west"))}), 200)
	setRegion(g["record"], tree)
	narrowUnit("uc3", u1["record"], "uc-one", "east", "west")
	require.Eventually(t, func() bool { st, h := state(g["record"]); return st == "held" && h == "uncomputable" }, 10*time.Second,
		100*time.Millisecond, "held, uncomputable")
	assert.Empty(t, segmentsOf(carol))
	// repaired, and its unit narrows again: computable now, the restore enters the effect point under the derived key;
	// wider than the unit now: effective with the intersection, to be reviewed (row 30)
	setRegion(g["record"], eastWest)
	heldAt := recordOf(t, admin, g["record"]).StateRev
	narrowUnit("uc4", u1["record"], "uc-one", "east")
	require.Eventually(t, func() bool { st, _ := state(g["record"]); return st == "active" }, 10*time.Second, 100*time.Millisecond,
		"restored")
	assert.True(t, reviewOf(t, admin, g["record"]), "partly outside: to be reviewed")
	assert.Equal(t, [][]string{{"east"}}, regionsOf(segmentsOf(carol)))
	assert.Equal(t, "applied", derivedBinding(t, admin, g["record"], int(heldAt), triggerRestore))
	// held and restored a second time: a new state revision, a new derived key, not answered by the first (CP81)
	setRegion(g["record"], tree)
	narrowUnit("uc4a", u1["record"], "uc-one", "east")
	require.Eventually(t, func() bool { st, _ := state(g["record"]); return st == "held" }, 10*time.Second, 100*time.Millisecond)
	setRegion(g["record"], eastWest)
	heldAgain := recordOf(t, admin, g["record"]).StateRev
	require.Greater(t, heldAgain, heldAt)
	narrowUnit("uc4b", u1["record"], "uc-one", "east")
	require.Eventually(t, func() bool { st, _ := state(g["record"]); return st == "active" }, 10*time.Second, 100*time.Millisecond,
		"restored again")
	assert.Equal(t, "applied", derivedBinding(t, admin, g["record"], int(heldAgain), triggerRestore))

	// held, then narrowed by a manager: still held, a new content revision (CP103); the narrowing moved its state
	// revision, and its unit's closure registers the restore again with the new content (CP115)
	u2 := submitChange(t, w, sectest.Alice, unitReq("uc5", root, "uc-two", []sdkauthz.Segment{orderSeg(region("east", "west", "north"))}, ops), 200)
	g2 := submitChange(t, w, sectest.Alice, grantReq("uc6", u2["record"], carol, []sdkauthz.Segment{orderSeg(region("east", "west"))}), 200)
	setRegion(g2["record"], tree)
	narrowUnit("uc7", u2["record"], "uc-two", "east", "west")
	require.Eventually(t, func() bool { st, _ := state(g2["record"]); return st == "held" }, 10*time.Second, 100*time.Millisecond)
	setRegion(g2["record"], eastWest) // repaired; no closure yet
	before := recordOf(t, admin, g2["record"])
	cand, _ := json.Marshal(map[string]any{"governance_unit": u2["record"], "grantee": carol, "segments": []sdkauthz.Segment{orderSeg(region("east"))}})
	narrowed := submitChange(t, w, sectest.Alice, map[string]any{"change_key": "uc8", "direction": "tighten", "target": g2["record"],
		"expected_state_revision": map[string]any{"domain": "authz.record.state", "value": strconv.FormatInt(before.StateRev, 10)},
		"candidate":               json.RawMessage(cand), "candidate_digest": candidateDigest("grant", cand)}, 200)
	assert.Equal(t, "applied", narrowed["outcome"])
	require.Eventually(t, func() bool { st, _ := state(g2["record"]); return st == "active" }, 10*time.Second, 100*time.Millisecond,
		"its unit's closure found it computable with the new content and restored it")
	after := recordOf(t, admin, g2["record"])
	assert.Equal(t, before.Revision+1, after.Revision, "the narrowing: a new content revision")
	assert.False(t, reviewOf(t, admin, g2["record"]), "within its unit")
	assert.Equal(t, "applied", derivedBinding(t, admin, g2["record"], int(before.StateRev+1), triggerRestore),
		"restored under the state revision the narrowing gave it")
	submitChange(t, w, sectest.Alice, tightenReq("uc9", g["record"]), 200)
	submitChange(t, w, sectest.Alice, tightenReq("uc10", g2["record"]), 200)
}
