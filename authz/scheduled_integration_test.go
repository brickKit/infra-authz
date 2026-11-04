//go:build integration

package authz

import (
	"context"
	"strconv"
	"testing"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordState is a record as the table has it.
type recordState struct {
	State, EndReason   string
	Revision, StateRev int64
	Predecessor        string
	Reason             string
}

func recordOf(t *testing.T, admin *pgx.Conn, id any) recordState {
	t.Helper()
	var r recordState
	var end, pred, why *string
	require.NoError(t, admin.QueryRow(context.Background(), `SELECT state, end_reason, revision, state_revision,
		predecessor::text, reason FROM `+itSchema+".authz_record WHERE id = $1", id).
		Scan(&r.State, &end, &r.Revision, &r.StateRev, &pred, &why))
	for p, v := range map[*string]*string{&r.EndReason: end, &r.Predecessor: pred, &r.Reason: why} {
		if v != nil {
			*p = *v
		}
	}
	return r
}

// dueItem is the timed work item registered for a record (P7.24).
type dueItem struct {
	State     string
	Attempts  int
	LastError string
}

func dueItemOf(t *testing.T, admin *pgx.Conn, record any) dueItem {
	t.Helper()
	var d dueItem
	var last *string
	require.NoError(t, admin.QueryRow(context.Background(), "SELECT state, attempts, last_error FROM "+itSchema+
		".be_work_item WHERE job = $1 AND args->>'record' = $2", JobDue, record).Scan(&d.State, &d.Attempts, &last))
	if last != nil {
		d.LastError = *last
	}
	return d
}

// derivedBinding is what the member bound under a job's derived key, "" when nothing.
func derivedBinding(t *testing.T, admin *pgx.Conn, record any, stateRev int, trigger string) string {
	t.Helper()
	var outcome string
	err := admin.QueryRow(context.Background(), "SELECT result->>'outcome' FROM "+itSchema+
		".authz_change WHERE requested_by = $1 AND change_key = $2", ID, record.(string)+":"+strconv.Itoa(stateRev)+":"+trigger).Scan(&outcome)
	if err == pgx.ErrNoRows {
		return ""
	}
	require.NoError(t, err)
	return outcome
}

// scheduledGrant is a grant effective in a while.
func scheduledGrant(key string, unit, grantee any, segs []sdkauthz.Segment, in time.Duration) map[string]any {
	r := grantReq(key, unit, grantee, segs)
	r["effective_from"] = time.Now().Add(in).UTC().Format(time.RFC3339Nano)
	return r
}

// testScheduled is T4d (security 08, "状态迁移" rows 2 and 6, decision table rows 3 and 29): a widening effective in
// the future is saved scheduled with a timed work item; when it is due the item enters the effect point under the
// derived key, and every check is made again then. inView verifies demo/orders' view and says whether the principal
// is in it.
func testScheduled(t *testing.T, w *sectest.World, admin *pgx.Conn, root, east string, inView func(string) bool) {
	seg := []sdkauthz.Segment{orderSeg(region("east"))}
	require.False(t, inView(carol), "the precondition: carol holds no grant")

	// due in two seconds: saved, the same key again answers the same record (CP61); no access before it is due
	req := scheduledGrant("d1", root, carol, seg, 2*time.Second)
	saved := submitChange(t, w, sectest.Alice, req, 202)
	assert.Equal(t, "scheduled", saved["outcome"])
	assert.Equal(t, map[string]any{"domain": "authz.record.state", "value": "1"}, saved["new_revision"])
	again := submitChange(t, w, sectest.Alice, req, 202)
	assert.Equal(t, saved["record"], again["record"], "the key is bound to the saved record: no second one")
	assert.Equal(t, "scheduled", recordOf(t, admin, saved["record"]).State)
	assert.Equal(t, dueItem{State: "pending"}, dueItemOf(t, admin, saved["record"]), "the work item is due at effective_from, never claimed before")
	assert.False(t, inView(carol), "scheduled: no access before it is due")
	// due: the job enters under the derived key, not the requester's (CP55), and the record takes effect
	require.Eventually(t, func() bool { return recordOf(t, admin, saved["record"]).State == "active" }, 10*time.Second,
		100*time.Millisecond, "the scheduled grant takes effect when it is due")
	assert.Equal(t, recordState{State: "active", Revision: 1, StateRev: 2}, recordOf(t, admin, saved["record"]))
	assert.Equal(t, "applied", derivedBinding(t, admin, saved["record"], 1, triggerScheduled))
	assert.Equal(t, "done", dueItemOf(t, admin, saved["record"]).State)
	assert.True(t, inView(carol), "effective: in the view")
	submitChange(t, w, sectest.Alice, tightenReq("d1r", saved["record"]), 200)

	// cancelled before it is due: the cancellation advances the state revision, so the job finds the record moved on
	// and is void (row 3; CP79, CP89): nothing changes, nothing is bound
	cancelled := submitChange(t, w, sectest.Alice, scheduledGrant("d2", root, carol, seg, 2*time.Second), 202)
	submitChange(t, w, sectest.Alice, map[string]any{"change_key": "d2c", "direction": "tighten", "termination": "cancel",
		"target": cancelled["record"], "expected_state_revision": map[string]any{"domain": "authz.record.state", "value": "1"}}, 200)
	assert.Equal(t, recordState{State: "ended", EndReason: "cancelled", Revision: 1, StateRev: 2}, recordOf(t, admin, cancelled["record"]))
	require.Eventually(t, func() bool { return dueItemOf(t, admin, cancelled["record"]).State == "done" }, 10*time.Second,
		100*time.Millisecond, "the job ran when due")
	assert.Equal(t, recordState{State: "ended", EndReason: "cancelled", Revision: 1, StateRev: 2}, recordOf(t, admin, cancelled["record"]),
		"a void job changes nothing")
	assert.Empty(t, derivedBinding(t, admin, cancelled["record"], 1, triggerScheduled), "a void job binds nothing")

	// the requester loses his management holding before it is due: rechecked when the job enters, row 8 rejects
	// for good, and the saved record ends rejected with the reason (CP68)
	var bobs string
	for _, h := range listRecords(t, w, sectest.Alice, "management_holding") {
		if b := h["body"].(map[string]any); b["holder"] == sectest.Bob && b["unit"] == east {
			bobs = h["id"].(string)
		}
	}
	require.NotEmpty(t, bobs, "the precondition: Bob manages the east unit")
	byBob := submitChange(t, w, sectest.Bob, scheduledGrant("d3", east, carol, seg, 3*time.Second), 202)
	submitChange(t, w, sectest.Alice, tightenReq("d3r", bobs), 200)
	require.Eventually(t, func() bool { return recordOf(t, admin, byBob["record"]).State == "ended" }, 10*time.Second,
		100*time.Millisecond, "the job decided")
	assert.Equal(t, recordState{State: "ended", EndReason: "rejected", Revision: 1, StateRev: 2, Reason: "PERMISSION_DENIED"},
		recordOf(t, admin, byBob["record"]))
	assert.Equal(t, "rejected", derivedBinding(t, admin, byBob["record"], 1, triggerScheduled), "a final rejection binds")
	assert.False(t, inView(carol))

	// renewals due later: one whose predecessor is still effective supersedes it then; one whose predecessor was
	// revoked meanwhile is rejected for good, not a new grant by surprise (row 17, A122). And a record still
	// scheduled whose state revision moved on (as when an administrator recovery sends it back to be confirmed and it
	// is scheduled again, CP89: made here in the table) voids the job registered before (row 3)
	renewal := func(key string, pred any) map[string]any {
		r := widenReq(key, "grant", map[string]any{"governance_unit": root, "grantee": carol, "segments": seg, "predecessor": pred})
		r["effective_from"] = time.Now().Add(2 * time.Second).UTC().Format(time.RFC3339Nano)
		return r
	}
	kept := submitChange(t, w, sectest.Alice, grantReq("d6a", root, carol, seg), 200)
	renewsKept := submitChange(t, w, sectest.Alice, renewal("d6", kept["record"]), 202)
	revoked := submitChange(t, w, sectest.Alice, grantReq("d7a", root, carol, seg), 200)
	renewsRevoked := submitChange(t, w, sectest.Alice, renewal("d7", revoked["record"]), 202)
	submitChange(t, w, sectest.Alice, tightenReq("d7r", revoked["record"]), 200)
	moved := submitChange(t, w, sectest.Alice, scheduledGrant("d8", root, carol, seg, 2*time.Second), 202)
	_, err := admin.Exec(context.Background(), "UPDATE "+itSchema+".authz_record SET state_revision = 3 WHERE id = $1", moved["record"])
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return recordOf(t, admin, renewsKept["record"]).State != "scheduled" && recordOf(t, admin, renewsRevoked["record"]).State != "scheduled" &&
			dueItemOf(t, admin, moved["record"]).State == "done"
	}, 10*time.Second, 100*time.Millisecond, "the three jobs ran")
	assert.Equal(t, recordState{State: "active", Revision: 1, StateRev: 2, Predecessor: kept["record"].(string)},
		recordOf(t, admin, renewsKept["record"]))
	assert.Equal(t, recordState{State: "ended", EndReason: "superseded", Revision: 1, StateRev: 2}, recordOf(t, admin, kept["record"]))
	assert.Equal(t, recordState{State: "ended", EndReason: "rejected", Revision: 1, StateRev: 2, Predecessor: revoked["record"].(string),
		Reason: "CHANGE_REVISION_STALE"}, recordOf(t, admin, renewsRevoked["record"]))
	assert.Equal(t, recordState{State: "scheduled", Revision: 1, StateRev: 3}, recordOf(t, admin, moved["record"]), "a void job changes nothing")
	assert.Empty(t, derivedBinding(t, admin, moved["record"], 1, triggerScheduled))
	submitChange(t, w, sectest.Alice, tightenReq("d6r", renewsKept["record"]), 200)
	submitChange(t, w, sectest.Alice, map[string]any{"change_key": "d8c", "direction": "tighten", "termination": "cancel",
		"target": moved["record"], "expected_state_revision": map[string]any{"domain": "authz.record.state", "value": "3"}}, 200)

	// a validity that ends before it would take effect never gives access: refused at once
	never := widenReq("d4", "grant", map[string]any{"governance_unit": root, "grantee": carol, "segments": seg,
		"valid": map[string]any{"from": "2026-01-01T00:00:00.000000Z", "until": time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}})
	never["effective_from"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	assert.Contains(t, submitChange(t, w, sectest.Alice, never, 400)["detail"], "after effective_from")
}
