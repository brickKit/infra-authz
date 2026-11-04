//go:build integration

package authz

import (
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Max is frozen at the identity member; Nina is frozen when this member first sees her account.
const (
	max  = "0190f3a1-0000-7000-8000-0000000000fd"
	nina = "0190f3a1-0000-7000-8000-0000000000fe"
)

// identitySide is T6c (security 08's identity-side dispositions): a freeze at the identity member makes a deployment-
// wide disposition of the person's every segment, holding its records (CP65); an unfreeze does not release it; a
// further mark is merged into its signals and advances its revision; a release removes the signals it names, and
// only when none is left do the records come back (CP114); once released, a mark on the still-disabled account makes
// no new one.
func (e *e2e) identitySide() {
	t, w, admin, ctx, root := e.t, e.w, e.admin, e.ctx, e.root
	of := func() (id, state string, revision int64, signals []string) {
		t.Helper()
		_ = admin.QueryRow(ctx, "SELECT id::text, state, revision, signal_ref FROM "+itSchema+".authz_disposition"+
			" WHERE subject = $1 AND origin = 'identity_side' ORDER BY created_at DESC LIMIT 1", max).Scan(&id, &state, &revision, &signals)
		return
	}
	count := func() (n int) {
		require.NoError(t, admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".authz_disposition WHERE subject = $1", max).Scan(&n))
		return
	}
	applied := func(version int64) { // the member applied this status of Max's account
		t.Helper()
		require.Eventually(t, func() bool {
			var v int64
			_ = admin.QueryRow(ctx, "SELECT version FROM "+itSchema+".be_projection WHERE projection = 'accounts' AND record_id = $1",
				max).Scan(&v)
			return v == version
		}, 10*time.Second, 100*time.Millisecond, "version %d applied", version)
	}
	release := func(key, id string, revision int64, refs ...string) (int, map[string]any) {
		return call(t, w, sectest.Alice, "POST", "/api/authz/dispositions/"+id+"/release", map[string]any{"change_key": key,
			"disposition_revision": map[string]any{"domain": dispositionDomain, "value": itoa64(revision)}, "signal_refs": refs})
	}

	require.NoError(t, e.iam.set(ctx, max, "active", 1))
	applied(1)
	g := submitChange(t, w, sectest.Alice, grantReq("is1", root, max, []sdkauthz.Segment{orderSeg(region("east"))}), 200)
	assert.Zero(t, count(), "the account seen the first time: no transition")

	// frozen: a disposition of every segment, the grant held (CP65)
	require.NoError(t, e.iam.set(ctx, max, "security_frozen", 2))
	applied(2)
	id, state, rev, signals := of()
	require.Equal(t, "active", state)
	assert.Equal(t, []string{max + "@2"}, signals)
	assert.Equal(t, "held", recordOf(t, admin, g["record"]).State)
	// unfrozen at the identity member: not released
	require.NoError(t, e.iam.set(ctx, max, "active", 3))
	applied(3)
	_, state, _, _ = of()
	assert.Equal(t, "active", state, "an unfreeze does not release it")
	// disabled as compromised: merged, its revision advanced
	require.NoError(t, e.iam.setMarked(ctx, max, "disabled", "compromised", 4))
	applied(4)
	_, _, rev, signals = of()
	assert.Equal(t, int64(2), rev)
	assert.Equal(t, []string{max + "@2", max + "@4"}, signals)
	assert.Equal(t, 1, count(), "one active identity-side disposition per account")

	// a release names the signals it removes; one left, nothing comes back (CP114)
	code, out := release("is2", id, rev)
	require.Equal(t, 400, code, "%v", out)
	code, out = release("is3", id, rev, max+"@2")
	require.Equal(t, 200, code, "%v", out)
	_, state, _, signals = of()
	assert.Equal(t, "active", state)
	assert.Equal(t, []string{max + "@4"}, signals)
	assert.Equal(t, "held", recordOf(t, admin, g["record"]).State)
	code, out = release("is4", id, rev, max+"@4")
	require.Equal(t, 200, code, "%v", out)
	_, state, _, _ = of()
	assert.Equal(t, "released", state)
	assert.Equal(t, "active", recordOf(t, admin, g["record"]).State, "the last signal removed: released")

	// released, the account still disabled: another mark is no transition
	require.NoError(t, e.iam.setMarked(ctx, max, "disabled", "suspicious", 5))
	applied(5)
	assert.Equal(t, 1, count())

	// an account first seen frozen: no transition from anything this member knew (security 08: "没有这一行"变为冻结不算)
	require.NoError(t, e.iam.set(ctx, nina, "security_frozen", 1))
	require.Eventually(t, func() bool {
		var n int
		_ = admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".authz_account_signal WHERE principal = $1", nina).Scan(&n)
		return n == 1
	}, 10*time.Second, 100*time.Millisecond, "her status applied")
	var n int
	require.NoError(t, admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".authz_disposition WHERE subject = $1", nina).Scan(&n))
	assert.Zero(t, n)
}
