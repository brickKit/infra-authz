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
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Kim manages the root (a plain management holding), Lee the east unit; both may release dispositions.
const (
	kim = "0190f3a1-0000-7000-8000-0000000000fb"
	lee = "0190f3a1-0000-7000-8000-0000000000fc"
)

// dispositionOf is the active disposition of subject made under change key key (by Alice).
func dispositionOf(t *testing.T, admin *pgx.Conn, key string) string {
	var id string
	require.NoError(t, admin.QueryRow(context.Background(), "SELECT id::text FROM "+itSchema+
		".authz_disposition WHERE change = $1", sectest.Alice+":"+key).Scan(&id))
	return id
}

// releases is T6b (security 08's release of a disposition): one change restores every record the disposition still
// holds and releases it (CP39); a record revoked meanwhile stays ended (CP88), one a renewal contains ends superseded
// (CP31); the disposed person does not release it (CP44), nor a manager of a smaller domain (CP53); releasing an
// authorization admin's disposition is a protected widening whose confirmation binds the disposition and its
// revision (CP63, CP71). It runs after the dispositions phase and uses what it made.
func (e *e2e) releases() {
	t, w, admin, ctx, root := e.t, e.w, e.admin, e.ctx, e.root
	_, err := admin.Exec(ctx, "UPDATE "+itSchema+".authz_record SET updated_at = now() - interval '25 hours'"+
		" WHERE record_type = 'management_holding' AND state <> 'active'") // a day passes (the cooling-off)
	require.NoError(t, err)
	release := func(who, key, id string, revision string, ids ...any) (int, map[string]any) {
		body := map[string]any{"change_key": key, "disposition_revision": map[string]any{"domain": effectpoint.DispositionDomain, "value": revision}}
		if len(ids) > 0 {
			body["confirmation_ids"] = ids
		}
		return call(t, w, who, "POST", "/api/authz/dispositions/"+id+"/release", body)
	}
	stateOf := func(id string) string {
		var st string
		require.NoError(t, admin.QueryRow(ctx, "SELECT state FROM "+itSchema+".authz_disposition WHERE id = $1", id).Scan(&st))
		return st
	}
	segs := []sdkauthz.Segment{}
	for _, op := range []string{core.OpDispRead, core.OpRelease} {
		segs = append(segs, sdkauthz.Segment{ResourceType: core.Dispositions, Operation: op, Atoms: map[string]sdkauthz.Atom{},
			ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}})
	}
	for _, p := range []struct{ who, unit string }{{kim, root}, {lee, e.east}} {
		require.NoError(t, e.iam.set(ctx, p.who, "active", 1))
		protect(t, w, sectest.Alice, holdingReq("rl-h-"+p.who, p.unit, p.who))
		submitChange(t, w, sectest.Alice, grantReq("rl-g-"+p.who, root, p.who, segs), 200)
	}
	refused := func(who, key, id string) map[string]any { // once the member's own view has their grants: refused
		t.Helper()
		var code int
		var out map[string]any
		require.Eventually(t, func() bool {
			code, out = release(who, key, id, "1")
			return code != 404 && code != 503
		}, 10*time.Second, 200*time.Millisecond, "%v", out)
		require.Equal(t, 403, code, "%v", out)
		return out
	}

	// Kim disposed in the east unit: he manages the root, but he is the disposed person (CP44)
	code, out := call(t, w, sectest.Alice, "POST", "/api/authz/dispositions", map[string]any{"change_key": "rel1", "subject": kim,
		"domain": e.east, "suspended_segments": []sdkauthz.Segment{orderSeg(region("east"))}})
	require.Equal(t, 200, code, "%v", out)
	kims := out["record"].(string)
	refused(kim, "rel2", kims)
	// Lee manages the east unit only: not the root's disposition of Grace (CP53)
	east := dispositionOf(t, admin, "ds3")
	refused(lee, "rel3", east)
	code, out = release(sectest.Alice, "rel4", kims, "1")
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "released", stateOf(kims))
	code, out = release(sectest.Alice, "rel4again", kims, "1")
	require.Equal(t, 409, code, "a released disposition is released once: %v", out)

	// a record revoked while held stays ended (CP88)
	code, out = call(t, w, sectest.Alice, "POST", "/api/authz/dispositions", map[string]any{"change_key": "rel5", "subject": grace,
		"suspended_segments": []sdkauthz.Segment{orderSeg(region("west"))}})
	require.Equal(t, 200, code, "%v", out)
	var west string
	require.NoError(t, admin.QueryRow(ctx, "SELECT id::text FROM "+itSchema+".authz_record WHERE disposition = $1", out["record"]).Scan(&west))
	submitChange(t, w, sectest.Alice, tightenReq("rel6", west), 200)
	code, out = release(sectest.Alice, "rel7", out["record"].(string), "1")
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "ended", recordOf(t, admin, west).State, "not brought back")

	// the root's disposition of the east: its held grant was renewed meanwhile, so it ends superseded; with the east
	// unit's and the records' dispositions released too, the east is given again (CP39, CP31)
	var held string
	require.NoError(t, admin.QueryRow(ctx, "SELECT id::text FROM "+itSchema+".authz_record WHERE disposition = $1", east).Scan(&held))
	ownerOf := func(id string) map[string]any { return ownerConfirmRelease(t, w, id) }
	elsewhere := ownerOf(east) // for Judy's release below: bound to another disposition
	code, out = release(sectest.Alice, "rel8s", east, "2")
	require.Equal(t, 409, code, "a revision the disposition does not have (final: it binds its key): %v", out)
	code, out = release(sectest.Alice, "rel8", east, "1")
	require.Equal(t, 200, code, "%v", out)
	require.Eventually(t, func() bool { // a release restores access: a general record (item 4 T6a)
		for _, r := range evidenceFor(w, east)["general"] {
			if r["category"] == "security_widening" {
				return true
			}
		}
		return false
	}, 10*time.Second, 100*time.Millisecond, "the release's evidence")
	assert.Equal(t, recordState{State: "ended", EndReason: "superseded", Revision: 1, StateRev: 3}, withoutReason(recordOf(t, admin, held)))
	for _, key := range []string{"ds8e", "ds11"} {
		code, out = release(sectest.Alice, "rel9-"+key, dispositionOf(t, admin, key), "1")
		require.Equal(t, 200, code, "%v", out)
	}
	require.Eventually(t, func() bool {
		var east, north bool
		for _, s := range e.segmentsOf(grace) {
			for _, v := range s.Atoms["region"].Values {
				east, north = east || v == "east", north || v == "north"
			}
		}
		return east && north
	}, 10*time.Second, 200*time.Millisecond, "the east is given again")

	// Judy's disposition: an authorization admin's, a protected widening; the owner confirms it bound to the
	// disposition at its revision, used once (CP63, CP71)
	judys := dispositionOf(t, admin, "ds10")
	code, out = release(sectest.Alice, "rel10", judys, "1")
	require.Equal(t, 202, code, "%v", out)
	assert.Equal(t, "awaiting_confirmation", out["outcome"])
	assert.Equal(t, "active", stateOf(judys))
	code, out = release(sectest.Alice, "rel10x", judys, "1", elsewhere["id"])
	require.Equal(t, 202, code, "a confirmation of another disposition is none: %v", out)
	assert.Equal(t, "active", stateOf(judys))
	c := ownerOf(judys)
	code, out = release(sectest.Alice, "rel10", judys, "1", c["id"])
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "released", stateOf(judys))
	var judyHolding string
	require.NoError(t, admin.QueryRow(ctx, "SELECT id::text FROM "+itSchema+`.authz_record WHERE record_type = 'management_holding'
		AND body->>'holder' = $1`, judy).Scan(&judyHolding))
	assert.Equal(t, "active", recordOf(t, admin, judyHolding).State)
	var used *string
	require.NoError(t, admin.QueryRow(ctx, "SELECT consumed_by_change FROM "+itSchema+".authz_confirmation WHERE id = $1", c["id"]).Scan(&used))
	assert.NotNil(t, used, "used when the release applied")

	// a held grant with nothing left within its unit's limit when released is kept held (restore_pending), for the
	// closure job to restore once it can; the release completes (CP66). Judy is available again: she confirms the unit
	ops := []string{"demo.order.read"}
	judySegs := []sdkauthz.Segment{}
	for _, op := range []string{core.OpRead, core.OpChange} {
		judySegs = append(judySegs, sdkauthz.Segment{ResourceType: core.Records, Operation: op, Atoms: map[string]sdkauthz.Atom{core.Holder: {Kind: "all"}},
			ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}})
	}
	submitChange(t, w, sectest.Alice, grantReq("rel10g", root, judy, judySegs), 200)
	waitForView(t, w, judy)
	rp := protectBy(t, w, sectest.Alice, judy, unitReq("rel11", root, "release-pending", []sdkauthz.Segment{orderSeg(region("east", "west"))}, ops))
	gr := submitChange(t, w, sectest.Alice, grantReq("rel12", rp["record"], grace, []sdkauthz.Segment{orderSeg(region("east"))}), 200)
	code, out = call(t, w, sectest.Alice, "POST", "/api/authz/dispositions", map[string]any{"change_key": "rel13", "subject": grace,
		"domain": rp["record"], "suspended_segments": []sdkauthz.Segment{orderSeg(region("east"))}})
	require.Equal(t, 200, code, "%v", out)
	pending := out["record"].(string)
	narrow := widenReq("rel14", "management_unit", map[string]any{"parent": root, "name": "release-pending",
		"managed_scope": []sdkauthz.Segment{orderSeg(region("west"))}, "grantable_operations": ops})
	narrow["direction"], narrow["target"] = "tighten", rp["record"]
	submitChange(t, w, sectest.Alice, narrow, 200)
	code, out = release(sectest.Alice, "rel15", pending, "1")
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "released", stateOf(pending))
	var hold string
	require.NoError(t, admin.QueryRow(ctx, "SELECT state || ':' || coalesce(hold_reason, '') FROM "+itSchema+
		".authz_record WHERE id = $1", gr["record"]).Scan(&hold))
	assert.Equal(t, "held:restore_pending", hold, "nothing of it within the unit's limit now")
}
