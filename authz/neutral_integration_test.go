//go:build integration

package authz

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testNeutral is a neutral change (security 08, "变更方向"): a display name changes as a new content revision with its
// audit record; no access changes, so the state revision and the security revision stay. Anything else in the
// candidate is a change of access, refused. Who may: as for a tightening.
func testNeutral(t *testing.T, w *sectest.World, admin *pgx.Conn, root, east string) {
	ctx := context.Background()
	var body map[string]any
	for _, u := range listRecords(t, w, sectest.Alice, "management_unit") {
		if u["id"] == east {
			body = u["body"].(map[string]any)
		}
	}
	require.NotNil(t, body, "the precondition: the east unit")
	before := recordOf(t, admin, east)
	counts := func() (secRev, audited int64) {
		require.NoError(t, admin.QueryRow(ctx, "SELECT security_revision FROM "+itSchema+".authz_state").Scan(&secRev))
		require.NoError(t, admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".be_audit_log WHERE category = 'security_change'").
			Scan(&audited))
		return
	}
	neutral := func(key string, change func(map[string]any)) map[string]any {
		cand := map[string]any{}
		for k, v := range body {
			cand[k] = v
		}
		change(cand)
		raw, _ := json.Marshal(cand)
		return map[string]any{"change_key": key, "direction": "neutral", "target": east, "candidate": json.RawMessage(raw),
			"candidate_digest":        candidateDigest("management_unit", raw),
			"expected_state_revision": map[string]any{"domain": "authz.record.state", "value": itoa64(before.StateRev)}}
	}
	sec0, aud0 := counts()
	renamed := submitChange(t, w, sectest.Alice, neutral("n1", func(c map[string]any) { c["name"] = "east (renamed)" }), 200)
	assert.Equal(t, "applied", renamed["outcome"])
	assert.Empty(t, renamed["security_revisions"], "no access changed: no new security revision")
	after := recordOf(t, admin, east)
	assert.Equal(t, before.Revision+1, after.Revision, "a new content revision")
	assert.Equal(t, before.StateRev, after.StateRev, "not a state transition: jobs registered for the record stay valid")
	sec1, aud1 := counts()
	assert.Equal(t, sec0, sec1)
	assert.Equal(t, aud0+1, aud1, "audited all the same")
	var name string
	require.NoError(t, admin.QueryRow(ctx, "SELECT body->>'name' FROM "+itSchema+".authz_record WHERE id = $1", east).Scan(&name))
	assert.Equal(t, "east (renamed)", name)

	// a name with anything else is a change of access: refused, split it
	both := submitChange(t, w, sectest.Alice, neutral("n2", func(c map[string]any) {
		c["name"], c["grantable_operations"] = "east again", []string{}
	}), 400)
	assert.Contains(t, both["detail"], "changes only the name")
	// Bob no longer manages the parent (his holding was revoked): row 8
	denied := submitChange(t, w, sectest.Bob, neutral("n3", func(c map[string]any) { c["name"] = "bob's" }), 403)
	assert.Equal(t, "PERMISSION_DENIED", denied["reason"])
	// a narrowing that renames is not a narrowing
	narrow := neutral("n4", func(c map[string]any) { c["name"], c["grantable_operations"] = "smaller", []string{} })
	narrow["direction"] = "tighten"
	assert.Contains(t, submitChange(t, w, sectest.Alice, narrow, 400)["detail"], "not within the record")

	// an ended record keeps its name: the start state is stale (row 4)
	gone := submitChange(t, w, sectest.Alice, unitReq("n5", root, "short-lived", []sdkauthz.Segment{orderSeg(region("east"))}, []string{}), 200)
	submitChange(t, w, sectest.Alice, tightenReq("n5r", gone["record"]), 200)
	late := map[string]any{"name": "too late", "parent": root, "managed_scope": []sdkauthz.Segment{orderSeg(region("east"))}, "grantable_operations": []string{}}
	raw, _ := json.Marshal(late)
	stale := submitChange(t, w, sectest.Alice, map[string]any{"change_key": "n6", "direction": "neutral", "target": gone["record"],
		"candidate": json.RawMessage(raw), "candidate_digest": candidateDigest("management_unit", raw)}, 409)
	assert.Equal(t, "CHANGE_REVISION_STALE", stale["reason"])
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }
