//go:build integration

package authz

import (
	"encoding/json"
	"testing"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// evidenceFor returns the records the test deployment's evidence store keeps about one object, by phase.
func evidenceFor(w *sectest.World, object string) map[string][]map[string]any {
	out := map[string][]map[string]any{}
	for _, raw := range w.Evidence() {
		var r map[string]any
		if json.Unmarshal(raw, &r) != nil {
			continue
		}
		if o, _ := r["object"].(map[string]any); o != nil && o["id"] == object {
			out[r["phase"].(string)] = append(out[r["phase"].(string)], r)
		}
	}
	return out
}

// evidenceByKey returns the records about the change with a change key, by phase.
func evidenceByKey(w *sectest.World, key string) map[string][]map[string]any {
	out := map[string][]map[string]any{}
	for _, raw := range w.Evidence() {
		var r map[string]any
		if json.Unmarshal(raw, &r) != nil {
			continue
		}
		if c, _ := r["change"].(map[string]any); c != nil && c["change_key"] == key {
			out[r["phase"].(string)] = append(out[r["phase"].(string)], r)
		}
	}
	return out
}

// TestChangesLeaveEvidence is item 4's T6a (assembly protocol 15's evidence table, be-protocol P12.15-P12.18): a
// widening that takes effect is a general record in its transaction; a tightening writes its intent before the
// effect point and its conclusion in it, effective with the commit position when it applied, cancelled when it did
// not; with the evidence store down the tightening still applies and its conclusion waits locally.
func TestChangesLeaveEvidence(t *testing.T) {
	e := startE2E(t)
	w, ctx, admin := e.w, e.ctx, e.admin
	seg := []sdkauthz.Segment{{ResourceType: Records, Operation: OpRead, Atoms: map[string]sdkauthz.Atom{Holder: {Kind: "all"}},
		ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}}} // this member's own resource
	units := listRecords(t, w, sectest.Alice, "management_unit")
	require.Len(t, units, 1)
	root := units[0]["id"].(string)
	g := submitChange(t, w, sectest.Alice, grantReq("ev-g1", root, sectest.Bob, seg), 200)
	rec := g["record"].(string)
	var got map[string][]map[string]any
	require.Eventually(t, func() bool { got = evidenceFor(w, rec); return len(got["general"]) == 1 }, 10*time.Second,
		100*time.Millisecond, "the grant's general record reaches the evidence store")
	gen := got["general"][0]
	assert.Equal(t, "security_widening", gen["category"])
	assert.NotNil(t, gen["position"], "committed with the grant")
	assert.Equal(t, map[string]any{"component": ID, "instance": gen["recorder"].(map[string]any)["instance"]}, gen["recorder"])

	// a revocation: the intent first, the effective conclusion with its position, the change history row
	code, out := call(t, w, sectest.Alice, "POST", "/api/authz/tightenings", tightenReq("ev-t1", rec))
	require.Equal(t, 200, code, "%v", out)
	require.Eventually(t, func() bool { got = evidenceFor(w, rec); return len(got["effective"]) == 1 }, 10*time.Second,
		100*time.Millisecond, "the revocation's conclusion")
	require.Len(t, got["intent"], 1)
	intent, eff := got["intent"][0], got["effective"][0]
	assert.Equal(t, intent["id"], eff["id"], "one record, two phases")
	assert.Equal(t, "security_tightening", intent["category"])
	assert.Nil(t, intent["position"])
	assert.NotNil(t, eff["position"])
	var hist int
	require.NoError(t, admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".be_change_history WHERE evidence_id = $1",
		eff["id"]).Scan(&hist))
	assert.Equal(t, 1, hist, "reflected by its id")

	// a tightening that does not apply (the record already ended): its intent is cancelled
	code, out = call(t, w, sectest.Alice, "POST", "/api/authz/tightenings", tightenReq("ev-t2", rec))
	require.NotEqual(t, 200, code, "%v", out)
	require.Eventually(t, func() bool { got = evidenceFor(w, rec); return len(got["cancelled"]) == 1 }, 10*time.Second,
		100*time.Millisecond, "the rejected tightening's cancelled conclusion")
	assert.Nil(t, got["cancelled"][0]["position"])
	// the same key again answers its bound result: no second conclusion, no second history row
	var before, after int
	require.NoError(t, admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".be_change_history").Scan(&before))
	code, _ = call(t, w, sectest.Alice, "POST", "/api/authz/tightenings", tightenReq("ev-t1", rec))
	require.Equal(t, 200, code)
	require.NoError(t, admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".be_change_history").Scan(&after))
	assert.Equal(t, before, after, "a bound result again concludes nothing")

	// the evidence store down: a revocation applies all the same; its conclusion waits in the evidence outbox
	g2 := submitChange(t, w, sectest.Alice, grantReq("ev-g2", root, sectest.Bob, seg), 200)
	rec2 := g2["record"].(string)
	w.EvidenceDown(true)
	code, out = call(t, w, sectest.Alice, "POST", "/api/authz/tightenings", tightenReq("ev-t3", rec2))
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "ended", recordOf(t, admin, rec2).State, "the tightening is not held back")
	var waiting int
	require.NoError(t, admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".be_evidence_outbox WHERE phase = 'effective'").Scan(&waiting))
	assert.Positive(t, waiting, "the conclusion waits locally")
	w.EvidenceDown(false)
	require.Eventually(t, func() bool { return len(evidenceFor(w, rec2)["effective"]) == 1 }, 10*time.Second,
		100*time.Millisecond, "sent once the store is back")
	assert.Empty(t, evidenceFor(w, rec2)["intent"], "no store, no alert channel: the intent was a double failure")
}
