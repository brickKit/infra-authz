//go:build integration

package itest

import (
	"encoding/json"
	"time"

	core "github.com/brickKit/infra-authz/v3/internal/core"
	effectpoint "github.com/brickKit/infra-authz/v3/internal/effectpoint"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Noah manages a unit that may re-delegate one level; Otto holds the unit he makes below it.
const (
	noah = "0190f3a1-0000-7000-8000-0000000000a5"
	otto = "0190f3a1-0000-7000-8000-0000000000a6"
)

// delegation is T7b (security 04's re-delegation and management actions, 09a's management_unit, A131): a child unit's
// actions are within its parent's and its depth below the parent's; a unit of depth 0 has no child; each management
// action is its own permission (grant, bind_role, revoke, delegate_management), what a unit gives is what every unit
// above it gives too, and a unit is never renewed under itself. It runs after the bounded phase; Judy confirms.
func (e *e2e) delegation() {
	t, w, ctx, root := e.t, e.w, e.ctx, e.root
	ops := []string{"demo.order.read"}
	scope := []sdkauthz.Segment{orderSeg(region("east", "west", "north"))}
	unitOf := func(parent, name string, depth int, actions ...string) map[string]any {
		return map[string]any{"parent": parent, "name": name, "managed_scope": scope, "grantable_operations": ops,
			"management_actions": actions, "max_subdelegation_depth": depth}
	}
	top := protectBy(t, w, sectest.Alice, judy, widenReq("dl1", "management_unit",
		unitOf(root, "dl-top", 1, effectpoint.ActGrant, effectpoint.ActRevoke, effectpoint.ActDelegate)))["record"].(string)
	mgr := []sdkauthz.Segment{}
	for _, op := range []string{core.OpRead, core.OpChange, core.OpTighten} {
		mgr = append(mgr, sdkauthz.Segment{ResourceType: core.Records, Operation: op, Atoms: map[string]sdkauthz.Atom{core.Holder: {Kind: "all"}},
			ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}})
	}
	for _, p := range []string{noah, otto} {
		require.NoError(t, e.iam.set(ctx, p, "active", 1))
		submitChange(t, w, sectest.Alice, grantReq("dl-m-"+p, root, p, mgr), 200)
	}
	protectBy(t, w, sectest.Alice, judy, holdingReq("dl-h1", top, noah))
	waitForView(t, w, noah)
	waitForView(t, w, otto)
	beyond := func(who, key string, body map[string]any) string {
		t.Helper()
		out := submitChange(t, w, who, widenReq(key, "management_unit", body), 403)
		require.Equal(t, "CONTAINMENT_NOT_PROVEN", out["reason"], "%v", out)
		return out["detail"].(string)
	}
	denied := func(who string, req map[string]any) {
		t.Helper()
		out := submitChange(t, w, who, req, 403)
		require.Equal(t, "PERMISSION_DENIED", out["reason"], "%v", out)
	}

	// re-delegation within the parent: fewer actions, a smaller depth (a protected widening: Judy confirms)
	child := protectBy(t, w, noah, judy, widenReq("dl2", "management_unit", unitOf(top, "dl-child", 0, effectpoint.ActGrant)))["record"].(string)
	assert.Contains(t, beyond(noah, "dl3", unitOf(top, "dl-wider", 0, effectpoint.ActGrant, effectpoint.ActBindRole)), "bind_role", "an action the parent has not")
	assert.Contains(t, beyond(noah, "dl4", unitOf(top, "dl-deep", 1, effectpoint.ActGrant)), "depth", "as deep as the parent")
	assert.Contains(t, beyond(noah, "dl5", unitOf(child, "dl-below", 0, effectpoint.ActGrant)), "depth", "below a unit of depth 0")
	out := submitChange(t, w, noah, widenReq("dl6", "management_unit", map[string]any{"parent": top, "name": "dl-bare",
		"managed_scope": scope, "grantable_operations": ops, "management_actions": []string{}, "max_subdelegation_depth": 0}), 400)
	assert.Equal(t, "REQUEST_INVALID", out["reason"], "a unit lists its actions: %v", out)

	// each action its own: Otto, who holds a unit that only grants, grants but neither revokes, binds a role, nor
	// delegates; Noah, above her, revokes what she granted
	protectBy(t, w, noah, judy, holdingReq("dl-h2", child, otto))
	g := submitChange(t, w, otto, grantReq("dl7", child, carol, []sdkauthz.Segment{orderSeg(region("east"))}), 200)
	denied(otto, tightenReq("dl8", g["record"]))
	role := submitChange(t, w, sectest.Alice, widenReq("dl-r", "role_revision", map[string]any{"name": "dl reader",
		"segments_template": []sdkauthz.Segment{orderSeg(region("east"))}}), 200)
	denied(otto, widenReq("dl9", "grant", map[string]any{"governance_unit": child, "grantee": carol, "role_revision": role["record"]}))
	denied(noah, widenReq("dl9n", "grant", map[string]any{"governance_unit": top, "grantee": carol, "role_revision": role["record"]}))
	denied(otto, widenReq("dl10", "management_unit", unitOf(child, "dl-ottos", 0, effectpoint.ActGrant)))
	denied(otto, holdingReq("dl10h", child, carol))
	submitChange(t, w, noah, tightenReq("dl11", g["record"]), 200)
	cancel := func(key string, target any) map[string]any {
		return map[string]any{"change_key": key, "direction": "tighten", "termination": "cancel", "target": target,
			"expected_state_revision": map[string]any{"domain": "authz.record.state", "value": "1"}}
	}
	later := submitChange(t, w, otto, scheduledGrant("dl11s", child, carol, []sdkauthz.Segment{orderSeg(region("north"))}, time.Hour), 202)
	denied(otto, cancel("dl11c", later["record"]))
	submitChange(t, w, noah, cancel("dl11n", later["record"]), 200)

	// the top narrowed to grant and delegate: Noah no longer revokes below it, nor does what he holds give it
	narrow := unitOf(root, "dl-top", 1, effectpoint.ActGrant, effectpoint.ActDelegate)
	raw, _ := json.Marshal(narrow)
	submitChange(t, w, sectest.Alice, map[string]any{"change_key": "dl12", "direction": "tighten", "target": top,
		"candidate": json.RawMessage(raw), "candidate_digest": effectpoint.CandidateDigest("management_unit", raw)}, 200)
	g2 := submitChange(t, w, otto, grantReq("dl13", child, carol, []sdkauthz.Segment{orderSeg(region("west"))}), 200)
	denied(noah, tightenReq("dl14", g2["record"]))
	wider := unitOf(root, "dl-top", 1, effectpoint.ActGrant, effectpoint.ActRevoke, effectpoint.ActDelegate)
	raw, _ = json.Marshal(wider)
	out = submitChange(t, w, sectest.Alice, map[string]any{"change_key": "dl15", "direction": "tighten", "target": top,
		"candidate": json.RawMessage(raw), "candidate_digest": effectpoint.CandidateDigest("management_unit", raw)}, 400)
	assert.Equal(t, "REQUEST_INVALID", out["reason"], "an action back is not a narrowing: %v", out)
	for key, body := range map[string]map[string]any{
		"dl15d": unitOf(root, "dl-top", 2, effectpoint.ActGrant, effectpoint.ActDelegate),                // a greater depth
		"dl15a": {"parent": root, "name": "dl-top", "managed_scope": scope, "grantable_operations": ops}, // no actions or depth
	} {
		raw, _ = json.Marshal(body)
		out = submitChange(t, w, sectest.Alice, map[string]any{"change_key": key, "direction": "tighten", "target": top,
			"candidate": json.RawMessage(raw), "candidate_digest": effectpoint.CandidateDigest("management_unit", raw)}, 400)
		assert.Equal(t, "REQUEST_INVALID", out["reason"], "%s: not a narrowing: %v", key, out)
	}

	// never under itself: the top renewed below its own child
	renewal := unitOf(child, "dl-top", 0, effectpoint.ActGrant)
	renewal["predecessor"] = top
	out = submitChange(t, w, sectest.Alice, widenReq("dl16", "management_unit", renewal), 400)
	assert.Contains(t, out["detail"], "under the unit it supersedes", "%v", out)
}
