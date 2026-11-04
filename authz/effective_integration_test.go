//go:build integration

package authz

import (
	"context"
	"encoding/json"
	"testing"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
// once, the grant itself unchanged and still active (partly outside: it stays effective). The effect point proves a
// new grant against the same effective limit. A permission key its owner no longer defines gives nothing.
// segmentsOf verifies demo/orders' view and returns a principal's segments in it.
func testEffective(t *testing.T, w *sectest.World, admin *pgx.Conn, root string, segmentsOf func(string) []sdkauthz.Segment) {
	ctx := context.Background()
	ops := []string{"demo.order.read"}
	require.Empty(t, segmentsOf(carol), "the precondition: carol holds no grant")
	wide := submitChange(t, w, sectest.Alice, unitReq("ef1", root, "wide", []sdkauthz.Segment{orderSeg(region("east", "west", "north"))}, ops), 200)
	sub := submitChange(t, w, sectest.Alice, unitReq("ef2", wide["record"], "wide-sub", []sdkauthz.Segment{orderSeg(region("east", "west"))}, ops), 200)
	g := submitChange(t, w, sectest.Alice, grantReq("ef3", sub["record"], carol, []sdkauthz.Segment{orderSeg(region("east", "west"))}), 200)
	assert.Equal(t, [][]string{{"east", "west"}}, regionsOf(segmentsOf(carol)))

	narrowWide := func(key string, regions ...string) {
		body := map[string]any{"name": "wide", "parent": root, "managed_scope": []sdkauthz.Segment{orderSeg(region(regions...))},
			"grantable_operations": ops}
		raw, _ := json.Marshal(body)
		submitChange(t, w, sectest.Alice, map[string]any{"change_key": key, "direction": "tighten", "target": wide["record"],
			"candidate": json.RawMessage(raw), "candidate_digest": candidateDigest("management_unit", raw)}, 200)
	}
	// the parent narrows: the grant keeps its segments, the view gives the intersection at once
	narrowWide("ef4", "east", "north")
	assert.Equal(t, [][]string{{"east"}}, regionsOf(segmentsOf(carol)), "{east, west} ∩ {east, west} ∩ {east, north}")
	assert.Equal(t, "active", recordOf(t, admin, g["record"]).State, "partly outside: still effective")
	assert.EqualValues(t, 1, recordOf(t, admin, g["record"]).Revision, "the grant itself unchanged")
	// narrowed past it: nothing left, the record still active (the closure job ends it, T4g)
	narrowWide("ef5", "north")
	assert.Empty(t, segmentsOf(carol), "{east, west} ∩ {north}: empty")
	assert.Equal(t, "active", recordOf(t, admin, g["record"]).State)
	// the effect point proves against the same effective limit: within the sub-unit's own scope, beyond its parent's
	beyond := submitChange(t, w, sectest.Alice, grantReq("ef6", sub["record"], carol, []sdkauthz.Segment{orderSeg(region("east"))}), 403)
	assert.Equal(t, "CONTAINMENT_NOT_PROVEN", beyond["reason"])
	submitChange(t, w, sectest.Alice, tightenReq("ef3r", g["record"]), 200)

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
