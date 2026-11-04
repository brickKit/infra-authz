//go:build integration

package authz

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reviewOf is a record's review flag (partly outside its limits).
func reviewOf(t *testing.T, admin *pgx.Conn, id any) bool {
	var r bool
	require.NoError(t, admin.QueryRow(context.Background(), "SELECT review FROM "+itSchema+".authz_record WHERE id = $1", id).Scan(&r))
	return r
}

// regionsOf is the region values a principal's segments in a view allow (nil: not in the view, or no segment).
func regionsOf(segs []sdkauthz.Segment) [][]string {
	var out [][]string
	for _, s := range segs {
		out = append(out, s.Atoms["region"].Values)
	}
	return out
}

// testEffective is T4f (security 08, "有效段的计算"): a view gives a grant's segments ∩ its governance unit's current
// limit, and a unit's limit is its scope ∩ its parent's, up to the root; a parent that narrows narrows the view at
// once, the grant itself unchanged and still active (partly outside: it stays effective); T4g's closure job then
// keeps the books. The effect point proves a new grant against the same effective limit. A role revision that ends,
// or a permission key its owner no longer defines, gives nothing.
// segmentsOf verifies demo/orders' view and returns a principal's segments in it.
func testEffective(t *testing.T, w *sectest.World, admin *pgx.Conn, root string, segmentsOf func(string) []sdkauthz.Segment) {
	ctx := context.Background()
	ops := []string{"demo.order.read"}
	require.Empty(t, segmentsOf(carol), "the precondition: carol holds no grant")
	wide := protect(t, w, sectest.Alice, unitReq("ef1", root, "wide", []sdkauthz.Segment{orderSeg(region("east", "west", "north"))}, ops))
	sub := protect(t, w, sectest.Alice, subUnitReq("ef2", wide["record"], "wide-sub", []sdkauthz.Segment{orderSeg(region("east", "west"))}, ops))
	g := submitChange(t, w, sectest.Alice, grantReq("ef3", sub["record"], carol, []sdkauthz.Segment{orderSeg(region("east", "west"))}), 200)
	assert.Equal(t, [][]string{{"east", "west"}}, regionsOf(segmentsOf(carol)))

	narrowWide := func(key string, regions ...string) {
		body := map[string]any{"name": "wide", "parent": root, "managed_scope": []sdkauthz.Segment{orderSeg(region(regions...))},
			"grantable_operations": ops}
		raw, _ := json.Marshal(unitDefaults(body))
		submitChange(t, w, sectest.Alice, map[string]any{"change_key": key, "direction": "tighten", "target": wide["record"],
			"candidate": json.RawMessage(raw), "candidate_digest": candidateDigest("management_unit", raw)}, 200)
	}
	bobs := protect(t, w, sectest.Alice, holdingReq("efh", sub["record"], sectest.Bob))
	// the parent narrows: the grant keeps its segments, the view gives the intersection at once; the closure job then
	// marks it partly outside, to be reviewed, still effective (security 08's closure)
	narrowWide("ef4", "east", "north")
	assert.Equal(t, [][]string{{"east"}}, regionsOf(segmentsOf(carol)), "{east, west} ∩ {east, west} ∩ {east, north}")
	require.Eventually(t, func() bool { return reviewOf(t, admin, g["record"]) }, 10*time.Second, 100*time.Millisecond,
		"partly outside: marked for review")
	assert.Equal(t, "active", recordOf(t, admin, g["record"]).State, "partly outside: still effective")
	assert.EqualValues(t, 1, recordOf(t, admin, g["record"]).Revision, "the grant itself unchanged")
	// the effect point proves against the same effective limit: within the sub-unit's own scope, beyond its parent's
	beyond := submitChange(t, w, sectest.Alice, grantReq("ef6", sub["record"], carol, []sdkauthz.Segment{orderSeg(region("west"))}), 403)
	assert.Equal(t, "CONTAINMENT_NOT_PROVEN", beyond["reason"])
	// narrowed past it: nothing left in the view at once; then the books: the sub-unit has nothing left
	// (source_narrowed), and what was under it lost its unit (source_ended)
	narrowWide("ef5", "north")
	assert.Empty(t, segmentsOf(carol), "{east, west} ∩ {north}: empty")
	require.Eventually(t, func() bool { return recordOf(t, admin, g["record"]).State == "ended" }, 10*time.Second,
		100*time.Millisecond, "the closure job keeps the books")
	// a protected unit: awaiting its confirmation (1), active (2), ended (3)
	assert.Equal(t, recordState{State: "ended", EndReason: "source_narrowed", Revision: 1, StateRev: 3}, recordOf(t, admin, sub["record"]))
	assert.Equal(t, recordState{State: "ended", EndReason: "source_ended", Revision: 1, StateRev: 2}, recordOf(t, admin, g["record"]))
	require.Eventually(t, func() bool { return recordOf(t, admin, bobs["record"]).State == "ended" }, 10*time.Second, 100*time.Millisecond)
	assert.Equal(t, "source_ended", recordOf(t, admin, bobs["record"]).EndReason, "a holding in a unit that ended")
	assert.Equal(t, recordState{State: "active", Revision: 3, StateRev: 4}, recordOf(t, admin, wide["record"]), "within the root")

	// a permission key its owner's definitions no longer have gives nothing, the grant unchanged
	conn := dial(t, w, "demo/invoices")
	src := sdkauthz.GRPCSource{Conn: conn}
	exportSeg := sdkauthz.Segment{ResourceType: "demo.invoice", Operation: "demo.invoice.export", Atoms: map[string]sdkauthz.Atom{},
		ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}}
	ex := submitChange(t, w, sectest.Alice, grantReq("ef7", root, carol, []sdkauthz.Segment{exportSeg}), 200)
	invoiceOps := func() []string {
		ans, err := src.Verify(ctx, sdkauthz.VerifyRequest{Component: "demo/invoices", Nonce: "n1"})
		require.NoError(t, err)
		var out []string
		for _, s := range ans.Shards[0].View.Subjects[carol].Segments {
			out = append(out, s.Operation)
		}
		return out
	}
	assert.Equal(t, []string{"demo.invoice.export"}, invoiceOps())
	without := *invoices
	without.Operations = invoices.Operations[:1]
	require.Equal(t, "demo.invoice.read", without.Operations[0].Key)
	require.NoError(t, without.Validate())
	require.NoError(t, without.Submit(ctx, authzv3.NewDefinitionServiceClient(conn), w.Deployment, "3.0.1"))
	assert.Empty(t, invoiceOps(), "the owner no longer defines the key: nothing")
	assert.Equal(t, "active", recordOf(t, admin, ex["record"]).State)
	submitChange(t, w, sectest.Alice, tightenReq("ef7r", ex["record"]), 200)
}

// testSources is the closure's other sources (security 08): a role revision that ends, a unit renewed (a new record
// superseding the old), a record's own validity, and an index that cannot say who is affected.
func testSources(t *testing.T, w *sectest.World, admin *pgx.Conn, root string, segmentsOf func(string) []sdkauthz.Segment) {
	ctx := context.Background()
	// a role revision that ends: a grant made from it gives nothing at once, and ends source_ended
	role := submitChange(t, w, sectest.Alice, widenReq("efr", "role_revision", map[string]any{"name": "order reader",
		"segments_template": []sdkauthz.Segment{orderSeg(region("east"))}}), 200)
	byRole := submitChange(t, w, sectest.Alice, widenReq("efr1", "grant", map[string]any{"governance_unit": root, "grantee": carol,
		"role_revision": role["record"]}), 200)
	assert.Equal(t, [][]string{{"east"}}, regionsOf(segmentsOf(carol)))
	submitChange(t, w, sectest.Alice, tightenReq("efr2", role["record"]), 200)
	assert.Empty(t, segmentsOf(carol), "its role revision ended: nothing")
	require.Eventually(t, func() bool { return recordOf(t, admin, byRole["record"]).State == "ended" }, 10*time.Second, 100*time.Millisecond)
	assert.Equal(t, "source_ended", recordOf(t, admin, byRole["record"]).EndReason)

	// a unit renewed wider is a new record superseding the old: what names the old one is under the new (its closure
	// finds them still within, nothing ends), and a grant naming the old ID is proved against the new limit
	old := protect(t, w, sectest.Alice, unitReq("efs", root, "renewable", []sdkauthz.Segment{orderSeg(region("east"))},
		[]string{"demo.order.read"}))
	under := submitChange(t, w, sectest.Alice, grantReq("efs1", old["record"], carol, []sdkauthz.Segment{orderSeg(region("east"))}), 200)
	protect(t, w, sectest.Alice, holdingReq("efsh", old["record"], sectest.Bob))
	renewed := protect(t, w, sectest.Alice, widenReq("efs2", "management_unit", map[string]any{"name": "renewable", "parent": root,
		"managed_scope": []sdkauthz.Segment{orderSeg(region("east", "west"))}, "grantable_operations": []string{"demo.order.read"},
		"predecessor": old["record"]}))
	assert.Equal(t, "superseded", recordOf(t, admin, old["record"]).EndReason)
	require.Eventually(t, func() bool {
		var st string
		_ = admin.QueryRow(ctx, "SELECT state FROM "+itSchema+".be_work_item WHERE job = $1 AND args->>'ref' = $2", JobClosure,
			old["record"]).Scan(&st)
		return st == "done"
	}, 10*time.Second, 100*time.Millisecond, "the old unit's closure ran")
	assert.Equal(t, "active", recordOf(t, admin, under["record"]).State, "still under the renewed unit")
	assert.False(t, reviewOf(t, admin, under["record"]))
	assert.Equal(t, [][]string{{"east"}}, regionsOf(segmentsOf(carol)), "still in the view")
	wider := submitChange(t, w, sectest.Alice, grantReq("efs3", old["record"], carol, []sdkauthz.Segment{orderSeg(region("west"))}), 200)
	assert.Equal(t, "applied", wider["outcome"], "the old ID is under the renewed unit's limit")
	byHolder := submitChange(t, w, sectest.Bob, grantReq("efs6", renewed["record"], carol, []sdkauthz.Segment{orderSeg(region("east"))}), 200)
	assert.Equal(t, "applied", byHolder["outcome"], "Bob's holding of the old unit is a holding of the renewed one")
	// the renewed unit narrows: its closure reaches what names the old ID too
	raw, _ := json.Marshal(unitDefaults(map[string]any{"name": "renewable", "parent": root, "managed_scope": []sdkauthz.Segment{orderSeg(region("east"))},
		"grantable_operations": []string{"demo.order.read"}}))
	submitChange(t, w, sectest.Alice, map[string]any{"change_key": "efs7", "direction": "tighten", "target": renewed["record"],
		"candidate": json.RawMessage(raw), "candidate_digest": candidateDigest("management_unit", raw)}, 200)
	require.Eventually(t, func() bool { return recordOf(t, admin, wider["record"]).State == "ended" }, 10*time.Second, 100*time.Millisecond,
		"west, under the old ID, has nothing left")
	assert.Equal(t, "source_narrowed", recordOf(t, admin, wider["record"]).EndReason)
	assert.Equal(t, "active", recordOf(t, admin, under["record"]).State)
	submitChange(t, w, sectest.Alice, tightenReq("efs4", under["record"]), 200)
	submitChange(t, w, sectest.Alice, tightenReq("efs5", byHolder["record"]), 200)

	// a record's validity ends: no access at once (evaluation), then its expiry item ends it expired (bookkeeping)
	short := widenReq("efe", "grant", map[string]any{"governance_unit": root, "grantee": carol,
		"segments": []sdkauthz.Segment{orderSeg(region("east"))},
		"valid":    map[string]any{"from": "2026-01-01T00:00:00.000000Z", "until": time.Now().Add(2 * time.Second).UTC().Format(time.RFC3339Nano)}})
	brief := submitChange(t, w, sectest.Alice, short, 200)
	assert.Equal(t, [][]string{{"east"}}, regionsOf(segmentsOf(carol)))
	require.Eventually(t, func() bool { return recordOf(t, admin, brief["record"]).State == "ended" }, 10*time.Second,
		100*time.Millisecond, "expired")
	assert.Equal(t, recordState{State: "ended", EndReason: "expired", Revision: 1, StateRev: 2}, recordOf(t, admin, brief["record"]))
	assert.Empty(t, segmentsOf(carol))

	// an index that cannot say who is affected is not "nobody": the closure scans, and the source domain is marked
	// for review
	other := protect(t, w, sectest.Alice, unitReq("efx", root, "other", []sdkauthz.Segment{orderSeg(region("east", "west"))},
		[]string{"demo.order.read"}))
	_, err := admin.Exec(ctx, "UPDATE "+itSchema+".authz_dependency_index SET complete = false WHERE kind = 'management_unit'")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "UPDATE "+itSchema+".authz_dependency_index SET complete = true")
	})
	var since time.Time
	require.NoError(t, admin.QueryRow(ctx, "SELECT now()").Scan(&since))
	raw, _ = json.Marshal(unitDefaults(map[string]any{"name": "other", "parent": root, "managed_scope": []sdkauthz.Segment{orderSeg(region("east"))},
		"grantable_operations": []string{"demo.order.read"}}))
	submitChange(t, w, sectest.Alice, map[string]any{"change_key": "efx1", "direction": "tighten", "target": other["record"],
		"candidate": json.RawMessage(raw), "candidate_digest": candidateDigest("management_unit", raw)}, 200)
	require.Eventually(t, func() bool {
		var n int
		require.NoError(t, admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".authz_review_domain WHERE kind = 'management_unit' AND ref = $1",
			other["record"]).Scan(&n))
		return n == 1
	}, 10*time.Second, 100*time.Millisecond, "the domain marked for review")
	closures := func() (n int) {
		require.NoError(t, admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".be_work_item WHERE job = $1 AND created_at >= $2",
			JobClosure, since).Scan(&n))
		return
	}
	for range 10 { // a second, on this goroutine (the admin connection is not safe for testify's polling goroutine)
		require.LessOrEqual(t, closures(), 1, "the scan covers every unit: it does not go on to each one's closure, which would scan again")
		time.Sleep(100 * time.Millisecond)
	}
	_, err = admin.Exec(ctx, "UPDATE "+itSchema+".authz_dependency_index SET complete = true WHERE kind = 'management_unit'")
	require.NoError(t, err)
}
