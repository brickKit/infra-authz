//go:build integration

package authz

import (
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/evidence"
	"github.com/brickKit/be-sdk-go/v3/ids"
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
	// its evidence says what a replay needs to release it again: the disposition and the signals (T13b)
	var rel map[string]any
	require.Eventually(t, func() bool {
		for _, r := range evidenceByKey(w, "is3")["general"] {
			rel, _ = r["change"].(map[string]any)["release"].(map[string]any)
		}
		return rel != nil
	}, 10*time.Second, 100*time.Millisecond, "the release's evidence")
	assert.Equal(t, id, rel["disposition"])
	assert.Equal(t, []any{max + "@2"}, rel["signal_refs"])
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

// identitySideRecovery is T13b (security 08's identity-side dispositions across a full recovery; assembly protocol
// 15's 6.3): the signal_ref is (account, the evidence record that froze or marked it), the same when the identity
// member replays the freeze (09a's evidence, written back with the original record); a replayed release finds its
// disposition by those refs, not by an identity a recovery re-derives; it waits (deferred) while a ref it names is
// not applied yet, and is applied once it is; it removes only the refs it names (CP73, CP102, CP107, CP112).
func (e *e2e) identitySideRecovery() {
	t, w, admin, ctx := e.t, e.w, e.admin, e.ctx
	const olga = "0190f3a1-0000-7000-8000-0000000000f7"
	version := int64(0)
	set := func(status, mark, evidenceID string) { // the identity member sends Olga's status; applied here
		t.Helper()
		version++
		require.NoError(t, e.iam.setEvidence(ctx, olga, status, mark, evidenceID, version))
		require.Eventually(t, func() bool {
			var v int64
			_ = admin.QueryRow(ctx, "SELECT version FROM "+itSchema+".be_projection WHERE projection = 'accounts' AND record_id = $1",
				olga).Scan(&v)
			return v == version
		}, 10*time.Second, 100*time.Millisecond, "version %d applied", version)
	}
	active := func() (id string, signals []string) {
		t.Helper()
		_ = admin.QueryRow(ctx, "SELECT id::text, signal_ref FROM "+itSchema+".authz_disposition WHERE subject = $1 AND "+
			"origin = 'identity_side' AND state = 'active'", olga).Scan(&id, &signals)
		return
	}
	client := evidence.ReplayClient{Conn: dial(t, w, "ops/recover")}
	release := func(disposition string, refs ...string) string { // a release as the evidence store keeps it, replayed
		t.Helper()
		rec, err := evidence.Seal(map[string]any{"record_type": evidence.RecordType, "schema": "1.0", "id": ids.New().String(),
			"recorder": map[string]any{"component": ID, "instance": "i"}, "category": "security_widening", "phase": "general",
			"position": map[string]any{"epoch": "1.1", "commit_seq": 1},
			"object":   map[string]any{"type": Records, "id": disposition, "version": "1"},
			"change": map[string]any{"direction": "release", "requested_by": sectest.Alice, "change_key": "rel-" + ids.New().String(),
				"release": map[string]any{"disposition": disposition, "signal_refs": refs}},
			"at": "2026-11-06T10:00:00.000000Z"})
		require.NoError(t, err)
		outcome, detail, err := client.Replay(ctx, rec.Record, "r1")
		require.NoError(t, err)
		require.NotEmpty(t, outcome, detail)
		return outcome
	}
	r1, r4, r5, r6, r7, r8 := ids.New().String(), ids.New().String(), ids.New().String(), ids.New().String(),
		ids.New().String(), ids.New().String()

	set("active", "", "") // seen the first time: no transition
	// CP73: frozen by the evidence record r1: a disposition keyed by it
	set("security_frozen", "", r1)
	d1, signals := active()
	require.NotEmpty(t, d1)
	assert.Equal(t, []string{olga + "@" + r1}, signals, "the signal_ref is the evidence record, not the revision")
	// CP102: its release replayed, naming the disposition as it was before the recovery (another identity): found by
	// its refs, released, no revision or confirmation asked again
	assert.Equal(t, evidence.Applied, release(ids.New().String(), olga+"@"+r1))
	d, _ := active()
	assert.Empty(t, d, "released")

	// a release whose ref is not applied yet: deferred, nothing done; applied once the freeze is
	set("active", "", "")
	assert.Equal(t, evidence.Deferred, release(ids.New().String(), olga+"@"+r4))
	set("security_frozen", "", r4)
	d4, _ := active()
	require.NotEmpty(t, d4)
	assert.Equal(t, evidence.Applied, release(ids.New().String(), olga+"@"+r4))
	d, _ = active()
	assert.Empty(t, d)

	// CP112: two signals merged (a freeze, then a compromised mark), both named: removed together, released
	set("active", "", "")
	set("security_frozen", "", r5)
	set("disabled", "compromised", r6)
	_, signals = active()
	assert.Equal(t, []string{olga + "@" + r5, olga + "@" + r6}, signals)
	assert.Equal(t, evidence.Applied, release(ids.New().String(), olga+"@"+r5, olga+"@"+r6))
	d, _ = active()
	assert.Empty(t, d)

	// CP107: freeze r7, unfreeze, freeze r8 merged into the same disposition; the release of r7 alone leaves r8: it
	// stays active
	set("active", "", "")
	set("security_frozen", "", r7)
	set("active", "", "")
	set("security_frozen", "", r8)
	d7, signals := active()
	assert.Equal(t, []string{olga + "@" + r7, olga + "@" + r8}, signals)
	assert.Equal(t, evidence.Applied, release(ids.New().String(), olga+"@"+r7))
	d, signals = active()
	assert.Equal(t, d7, d, "still active")
	assert.Equal(t, []string{olga + "@" + r8}, signals)
}
