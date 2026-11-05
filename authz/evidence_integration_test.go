//go:build integration

package authz

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/evidence"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/jackc/pgx/v5"
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

// TestTheReplayAppliesTheEvidenceAgain is item 4's T9c (be-protocol P12.19-P12.21, assembly protocol 15's 6.3): a
// grant and its revocation, then the database put back to before both (a restore to T); the recovery tool replays
// them in their commit order: the grant comes back under its own identity, the revocation ends it again, each once
// (again: reflected). A revocation of a record that is gone is dangling.
func TestTheReplayAppliesTheEvidenceAgain(t *testing.T) {
	e := startE2E(t)
	w, ctx, admin := e.w, e.ctx, e.admin
	seg := []sdkauthz.Segment{{ResourceType: Records, Operation: OpRead, Atoms: map[string]sdkauthz.Atom{Holder: {Kind: "all"}},
		ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}}}
	units := listRecords(t, w, sectest.Alice, "management_unit")
	require.Len(t, units, 1)
	g := submitChange(t, w, sectest.Alice, grantReq("rp-g1", units[0]["id"].(string), sectest.Bob, seg), 200)
	rec := g["record"].(string)
	code, out := call(t, w, sectest.Alice, "POST", "/api/authz/tightenings", tightenReq("rp-t1", rec))
	require.Equal(t, 200, code, "%v", out)
	var got map[string][]map[string]any
	require.Eventually(t, func() bool { got = evidenceFor(w, rec); return len(got["effective"]) == 1 && len(got["general"]) == 1 },
		10*time.Second, 100*time.Millisecond)
	raw := func(r map[string]any) []byte {
		for k, v := range w.Evidence() {
			if strings.HasPrefix(k, r["id"].(string)+"/") && strings.HasSuffix(k, "/"+r["phase"].(string)) {
				return v
			}
		}
		t.Fatalf("no raw record %v", r["id"])
		return nil
	}
	grant, revoke := raw(got["general"][0]), raw(got["effective"][0])
	assert.Contains(t, string(grant), `"candidate"`, "a widening's evidence carries what a replay applies again")

	// the database as it was before both: the record, its index and the two changes' bindings and history gone
	for _, q := range []string{
		"DELETE FROM " + itSchema + ".authz_dependency WHERE record = $1",
		"DELETE FROM " + itSchema + ".authz_change WHERE result->>'record' = $1",
		"DELETE FROM " + itSchema + ".authz_record WHERE id = $1",
	} {
		_, err := admin.Exec(ctx, q, rec)
		require.NoError(t, err, q)
	}
	for _, r := range []map[string]any{got["general"][0], got["effective"][0]} {
		_, err := admin.Exec(ctx, "DELETE FROM "+itSchema+".be_change_history WHERE evidence_id = $1", r["id"])
		require.NoError(t, err)
	}
	client := evidence.ReplayClient{Conn: dial(t, w, "ops/recover")}
	replay := func(b []byte) string {
		t.Helper()
		outcome, detail, err := client.Replay(ctx, b, "r1")
		require.NoError(t, err)
		require.NotEmpty(t, outcome, detail)
		return outcome
	}
	assert.Equal(t, evidence.Applied, replay(grant), "the grant again, in commit order first")
	assert.Equal(t, "active", recordOf(t, admin, rec).State, "under its own identity")
	assert.Equal(t, evidence.Applied, replay(revoke), "then its revocation")
	assert.Equal(t, "ended", recordOf(t, admin, rec).State)
	assert.Equal(t, evidence.AlreadyReflected, replay(grant))
	assert.Equal(t, evidence.AlreadyReflected, replay(revoke))
	history := func() []string {
		rows, err := admin.Query(ctx, "SELECT evidence_id::text FROM "+itSchema+".be_change_history WHERE object_id = $1", rec)
		require.NoError(t, err)
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		require.NoError(t, err)
		return ids
	}
	assert.ElementsMatch(t, []string{got["general"][0]["id"].(string), got["effective"][0]["id"].(string)}, history(),
		"the replay writes the history under the records' own identities, no new evidence of its own")

	// a revocation of a record that ended since (restored after its end, the revocation not reflected): nothing left
	// to tighten, the replay accepts it
	_, err := admin.Exec(ctx, "DELETE FROM "+itSchema+".be_change_history WHERE evidence_id = $1", got["effective"][0]["id"])
	require.NoError(t, err)
	_, err = admin.Exec(ctx, "DELETE FROM "+itSchema+".authz_change WHERE change_key = 'rp-t1'")
	require.NoError(t, err)
	assert.Equal(t, evidence.Applied, replay(revoke), "the record is ended already")
	assert.Equal(t, "ended", recordOf(t, admin, rec).State)

	// the business preconditions held when the change was made and are not decided again: a revocation by an admin who
	// holds no management role any more (in the restored database, or since) is applied all the same
	g2 := submitChange(t, w, sectest.Alice, grantReq("rp-g2", units[0]["id"].(string), sectest.Bob, seg), 200)
	rec2 := g2["record"].(string)
	former, err := evidence.Seal(map[string]any{"record_type": evidence.RecordType, "schema": "1.0", "id": ids.New().String(),
		"recorder": map[string]any{"component": ID, "instance": "i"}, "category": "security_tightening", "phase": "intent",
		"object": map[string]any{"type": Records, "id": rec2},
		"change": map[string]any{"direction": Tighten, "requested_by": "0190f3a1-0000-7000-8000-0000000000c3",
			"change_key": "rp-t2", "target": rec2}, "at": "2026-11-05T10:00:00.000000Z"})
	require.NoError(t, err)
	assert.Equal(t, evidence.Applied, replay(former.Record), "the requester's eligibility is not decided again")
	assert.Equal(t, "ended", recordOf(t, admin, rec2).State)

	gone, err := evidence.Seal(map[string]any{"record_type": evidence.RecordType, "schema": "1.0", "id": ids.New().String(),
		"recorder": map[string]any{"component": ID, "instance": "i"}, "category": "security_tightening", "phase": "intent",
		"object": map[string]any{"type": Records, "id": ids.New().String()},
		"change": map[string]any{"direction": Tighten, "requested_by": sectest.Alice, "change_key": "rp-t9",
			"target": ids.New().String()}, "at": "2026-11-05T10:00:00.000000Z"})
	require.NoError(t, err)
	assert.Equal(t, evidence.Dangling, replay(gone.Record))
}
