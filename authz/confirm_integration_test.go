//go:build integration

package authz

import (
	"context"
	"testing"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testConfirmations is T5a (security 08's confirmation records, 09a's be.security.confirmation, A123): another
// authorization admin confirms a tightening of a record at its revision; the requester attaches it; it is used once.
// A confirmation that does not hold (used, someone else's target, the requester's own, the object's own, expired, an
// older revision) is no confirmation: a tightening that carries one waits for a valid one (row 24).
func testConfirmations(t *testing.T, w *sectest.World, admin *pgx.Conn, root string) {
	ctx := context.Background()
	seg := []sdkauthz.Segment{orderSeg(region("east"))}
	confirm := func(who string, target any, revision int64) (int, map[string]any) {
		return call(t, w, who, "POST", "/api/authz/confirmations", map[string]any{"target": target,
			"expected_revision": map[string]any{"domain": "authz.record.revision", "value": itoa64(revision)}})
	}
	revokeWith := func(key string, target any, ids ...any) (int, map[string]any) {
		r := tightenReq(key, target)
		r["confirmation_ids"] = ids
		return call(t, w, sectest.Alice, "POST", "/api/authz/changes", r)
	}

	// only an authorization admin confirms (A123): Bob manages records, holds no such role yet
	g := submitChange(t, w, sectest.Alice, grantReq("cf1", root, carol, seg), 200)
	code, out := confirm(sectest.Bob, g["record"], 1)
	require.Equal(t, 403, code, "%v", out)
	assert.Equal(t, "PERMISSION_DENIED", out["reason"])
	bobAdmin := submitChange(t, w, sectest.Alice, widenReq("cf2", "management_holding",
		map[string]any{"unit": root, "holder": sectest.Bob, "system_role": "authorization_admin"}), 200)
	waitForView(t, w, sectest.Bob)

	// a valid confirmation: the revocation applies, the confirmation is used by it
	code, c1 := confirm(sectest.Bob, g["record"], 1)
	require.Equal(t, 201, code, "%v", c1)
	code, out = revokeWith("cf3", g["record"], c1["id"])
	require.Equal(t, 200, code, "%v", out)
	var used *string
	require.NoError(t, admin.QueryRow(ctx, "SELECT consumed_by_change FROM "+itSchema+".authz_confirmation WHERE id = $1", c1["id"]).Scan(&used))
	require.NotNil(t, used, "used by the change that applied")
	assert.Equal(t, sectest.Alice+":cf3", *used)

	g2 := submitChange(t, w, sectest.Alice, grantReq("cf4", root, carol, seg), 200)
	waiting := func(key string, ids ...any) {
		t.Helper()
		code, out := revokeWith(key, g2["record"], ids...)
		require.Equal(t, 202, code, "%v", out)
		assert.Equal(t, "awaiting_confirmation", out["outcome"])
		assert.Equal(t, "CONFIRMATION_REQUIRED", out["reason"])
		assert.Equal(t, "active", recordOf(t, admin, g2["record"]).State, "a tightening waiting for its confirmation changes nothing")
	}
	waiting("cf5", c1["id"]) // used already, and for another record
	_, own := confirm(sectest.Alice, g2["record"], 1)
	require.NotEmpty(t, own["id"], "the requester may record a confirmation; it never counts for her own change")
	waiting("cf6", own["id"])
	_, stale := confirm(sectest.Bob, g2["record"], 2)
	waiting("cf7", stale["id"]) // for a revision the record does not have
	_, late := confirm(sectest.Bob, g2["record"], 1)
	_, err := admin.Exec(ctx, "UPDATE "+itSchema+".authz_confirmation SET expires_at = now() - interval '1 second' WHERE id = $1", late["id"])
	require.NoError(t, err)
	waiting("cf8", late["id"])
	code, out = revokeWith("cf9", g2["record"], "01a1a6a0-0000-7000-8000-000000000000")
	require.Equal(t, 202, code, "an unknown confirmation is no confirmation: %v", out)

	// the object of the change never confirms it: Bob's own holding, revoked by Alice with Bob's confirmation
	_, bobs := confirm(sectest.Bob, bobAdmin["record"], 1)
	code, out = revokeWith("cf10", bobAdmin["record"], bobs["id"])
	require.Equal(t, 202, code, "%v", out)
	assert.Equal(t, "active", recordOf(t, admin, bobAdmin["record"]).State)

	// valid in every other way, but for another record
	g3 := submitChange(t, w, sectest.Alice, grantReq("cf12", root, carol, seg), 200)
	_, elsewhere := confirm(sectest.Bob, g3["record"], 1)
	waiting("cf13", elsewhere["id"])

	_, fresh := confirm(sectest.Bob, g2["record"], 1)
	code, out = revokeWith("cf11", g2["record"], fresh["id"])
	require.Equal(t, 200, code, "%v", out)

	// the confirmer is checked again when the change enters: Bob no longer an admin, his confirmation no longer holds
	_, before := confirm(sectest.Bob, g3["record"], 1)
	submitChange(t, w, sectest.Alice, tightenReq("cf14", bobAdmin["record"]), 200)
	code, out = revokeWith("cf15", g3["record"], before["id"])
	require.Equal(t, 202, code, "%v", out)
	assert.Equal(t, "active", recordOf(t, admin, g3["record"]).State)
	submitChange(t, w, sectest.Alice, tightenReq("cf16", g3["record"]), 200)
}
