//go:build integration

package authz

import (
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Judy joins for the dispositions: an authorization admin to be disposed.
const judy = "0190f3a1-0000-7000-8000-0000000000fa"

// dispositions is T6a (security 08's security dispositions, A128): a disposition holds the person's records in its
// scope (security_hold) and, while active, leaves every segment of the person that meets the suspended scope out of
// the views whole — a renewal of a held grant takes effect but gives nothing there (CP31), a disjoint grant goes on
// (CP43); the disposed person cannot give up what is held (CP110); the scope is within the domain's limit; disposing
// another authorization admin is protected, the owner stands in when no one else is available (CP52, CP93).
func (e *e2e) dispositions() {
	t, w, admin, ctx, root := e.t, e.w, e.admin, e.ctx, e.root
	// a day passes: the admins who became unavailable in the phases before are outside the cooling-off
	_, err := admin.Exec(ctx, "UPDATE "+itSchema+".authz_record SET updated_at = now() - interval '25 hours'"+
		" WHERE record_type = 'management_holding' AND state <> 'active'")
	require.NoError(t, err)
	regions := func(p string) []string {
		var out []string
		for _, s := range e.segmentsOf(p) {
			if s.ResourceType == "demo.order" {
				out = append(out, s.Atoms["region"].Values...)
			}
		}
		return out
	}
	dispose := func(key string, body map[string]any) (int, map[string]any) {
		body["change_key"] = key
		return call(t, w, sectest.Alice, "POST", "/api/authz/dispositions", body)
	}

	east := submitChange(t, w, sectest.Alice, grantReq("ds1", root, grace, []sdkauthz.Segment{orderSeg(region("east"))}), 200)
	submitChange(t, w, sectest.Alice, grantReq("ds2", root, grace, []sdkauthz.Segment{orderSeg(region("west"))}), 200)
	require.Eventually(t, func() bool { return len(regions(grace)) == 2 }, 10*time.Second, 200*time.Millisecond, "the precondition")

	// suspended: the east; the grant that meets it is held, the other one stays, and only the west is given (CP43)
	code, out := dispose("ds3", map[string]any{"subject": grace, "suspended_segments": []sdkauthz.Segment{orderSeg(region("east"))}})
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, recordState{State: "held", Revision: 1, StateRev: 2}, withoutReason(recordOf(t, admin, east["record"])))
	assert.Equal(t, []string{"west"}, regions(grace))
	var op string
	require.NoError(t, admin.QueryRow(ctx, "SELECT operation FROM "+itSchema+".be_audit_log WHERE target->>'id' = $1",
		out["record"]).Scan(&op))
	assert.Equal(t, OpDispose, op)
	// its evidence: the intent carries the disposition itself, what a replay applies again (item 4 T6a, P12.9)
	var dispEv map[string][]map[string]any
	require.Eventually(t, func() bool { dispEv = evidenceByKey(w, "ds3"); return len(dispEv["effective"]) == 1 }, 10*time.Second,
		100*time.Millisecond, "the disposition's evidence")
	require.Len(t, dispEv["intent"], 1)
	cand, _ := dispEv["intent"][0]["change"].(map[string]any)["candidate"].(map[string]any)
	assert.Equal(t, grace, cand["subject"], "the candidate in the evidence: %v", dispEv["intent"][0]["change"])

	// a renewal of the held grant takes effect, and a new grant over the east too; neither gives the east (CP31)
	renewal := widenReq("ds4", "grant", map[string]any{"governance_unit": root, "grantee": grace, "predecessor": east["record"],
		"segments": []sdkauthz.Segment{orderSeg(region("east"))}})
	renewed := submitChange(t, w, sectest.Alice, renewal, 200)
	assert.Equal(t, "active", recordOf(t, admin, renewed["record"]).State)
	assert.Equal(t, "held", recordOf(t, admin, east["record"]).State, "the release ends it superseded, not the renewal")
	wide := submitChange(t, w, sectest.Alice, grantReq("ds5", root, grace, []sdkauthz.Segment{orderSeg(region("east", "north"))}), 200)
	assert.Equal(t, []string{"west"}, regions(grace), "whatever a segment comes from, it is left out when it meets the scope")

	// the disposed person does not give up what the disposition holds (CP110)
	require.Eventually(t, func() bool {
		code, out = call(t, w, grace, "POST", "/api/authz/relinquishments", tightenReq("ds6", east["record"]))
		return code == 403
	}, 10*time.Second, 200*time.Millisecond, "%v", out)
	assert.Equal(t, "held", recordOf(t, admin, east["record"]).State)

	// within the domain's limit only: the east unit suspends nothing in the west
	code, out = dispose("ds7", map[string]any{"subject": grace, "domain": e.east,
		"suspended_segments": []sdkauthz.Segment{orderSeg(region("west"))}})
	require.Equal(t, 403, code, "%v", out)
	assert.Equal(t, "CONTAINMENT_NOT_PROVEN", out["reason"])
	code, out = dispose("ds8", map[string]any{"subject": grace, "domain": e.east, "all_scope": true})
	require.Equal(t, 400, code, "every segment is the root's to suspend: %v", out)
	// a domain holds the records governed in it or below: the root's grant meeting the scope stays effective (the
	// views leave it out all the same)
	code, out = dispose("ds8e", map[string]any{"subject": grace, "domain": e.east,
		"suspended_segments": []sdkauthz.Segment{orderSeg(region("east"))}})
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "active", recordOf(t, admin, wide["record"]).State, "governed above the domain")

	// the operation alone is not the right: Heidi may dispose but manages no unit (row 8)
	heidiSegs := []sdkauthz.Segment{}
	for _, op := range []string{OpDispRead, OpDispose} {
		heidiSegs = append(heidiSegs, sdkauthz.Segment{ResourceType: Dispositions, Operation: op, Atoms: map[string]sdkauthz.Atom{},
			ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}})
	}
	submitChange(t, w, sectest.Alice, grantReq("ds8h", root, heidi, heidiSegs), 200)
	require.Eventually(t, func() bool {
		code, out = call(t, w, heidi, "POST", "/api/authz/dispositions", map[string]any{"change_key": "ds8x", "subject": grace,
			"suspended_segments": []sdkauthz.Segment{orderSeg(region("west"))}})
		return code != 404 && code != 503 // her grant reached the member's own view
	}, 10*time.Second, 200*time.Millisecond, "%v", out)
	require.Equal(t, 403, code, "%v", out)
	assert.Equal(t, "PERMISSION_DENIED", out["reason"])
	assert.Equal(t, []string{"west"}, regions(grace), "nothing changed")

	// another authorization admin: a protected tightening; with no one else available the owner confirms (CP52, CP93)
	require.NoError(t, e.iam.set(ctx, judy, "active", 1))
	judyAdmin := protect(t, w, sectest.Alice, widenReq("ds9", "management_holding",
		map[string]any{"unit": root, "holder": judy, "system_role": "authorization_admin"}))
	whole := map[string]any{"subject": judy, "all_scope": true}
	code, out = dispose("ds10", whole)
	require.Equal(t, 202, code, "%v", out)
	assert.Equal(t, "awaiting_confirmation", out["outcome"])
	assert.Equal(t, "active", recordOf(t, admin, judyAdmin["record"]).State)
	byOwner := ownerConfirm(t, w, sectest.Alice, judyAdmin["record"], "1")
	whole["confirmation_ids"] = []any{byOwner["id"]}
	code, out = dispose("ds10", whole)
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "held", recordOf(t, admin, judyAdmin["record"]).State, "not held back by the last admin: Alice remains anyway")

	// the fixed segments to see and give up one's own records (D82) are segments like any: Grace's reading of her own
	// records suspended, she sees none of them
	own := func() int {
		code, out := call(t, w, grace, "GET", "/api/authz/records?type=grant", nil)
		require.Equal(t, 200, code, "%v", out)
		recs, _ := out["records"].([]any) // an empty page: null
		return len(recs)
	}
	require.Positive(t, own(), "the precondition: she sees her own grants")
	code, out = dispose("ds11", map[string]any{"subject": grace, "suspended_segments": []sdkauthz.Segment{{ResourceType: Records,
		Operation: OpRead, Atoms: map[string]sdkauthz.Atom{Holder: {Kind: "all"}}, ReadFields: []string{"id"},
		Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}}}})
	require.Equal(t, 200, code, "%v", out)
	require.Eventually(t, func() bool { return own() == 0 }, 10*time.Second, 200*time.Millisecond, "her own records: left out")
	code, list := call(t, w, sectest.Alice, "GET", "/api/authz/dispositions", nil)
	require.Equal(t, 200, code, "%v", list)
	mine := 0 // the identity-side ones the phases before derived are in the list too (T6c)
	for _, d := range list["dispositions"].([]any) {
		if d.(map[string]any)["body"].(map[string]any)["origin"] == "admin" {
			mine++
		}
	}
	assert.Equal(t, 4, mine, "the four this phase made")
}

// withoutReason is a record's state without the reason (a hold has none to compare).
func withoutReason(r recordState) recordState {
	r.Reason = ""
	return r
}
