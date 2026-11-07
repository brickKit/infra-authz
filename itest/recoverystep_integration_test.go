//go:build integration

package itest

import (
	"strconv"
	"testing"
	"time"

	adminrecovery "github.com/brickKit/infra-authz/v3/internal/adminrecovery"
	core "github.com/brickKit/infra-authz/v3/internal/core"
	effectpoint "github.com/brickKit/infra-authz/v3/internal/effectpoint"
	restore "github.com/brickKit/infra-authz/v3/internal/restore"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/evidence"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/brickKit/be-sdk-go/v3/recoverypb"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestTheRecoveryStepAfterTheReplay is item 4's T9c for a full recovery's 6.4-6.5 (assembly protocol 15; A142): the
// recovery tool learns when the identity source's replay is applied, the invariant check keeps the books of the final
// state and closes the subjects under review (an admin stays open), and a deferred intent-only revocation that would
// leave no admin is not executed: its subject is closed and the deployment awaits an administrator recovery.
func TestTheRecoveryStepAfterTheReplay(t *testing.T) {
	e := startE2E(t)
	w, ctx, admin := e.w, e.ctx, e.admin
	rc := authzv3.NewRecoveryServiceClient(dial(t, w, restore.RecoveryTool))
	_, err := authzv3.NewRecoveryServiceClient(dial(t, w, "demo/orders")).Sources(ctx, &authzv3.SourcesRequest{})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "the recovery tool only: %v", err)

	// 6.4: what the source committed before the moment is applied once every source answers so
	require.NoError(t, e.iam.set(ctx, dave, "disabled", 2))
	first, err := rc.Sources(ctx, &authzv3.SourcesRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, first.GetAsOf())
	require.Len(t, first.GetSources(), 1)
	assert.Equal(t, iamID, first.GetSources()[0].GetComponent())
	assert.False(t, first.GetAllApplied(), "the watermark is from a pull before the moment")
	var last *authzv3.SourcesResponse
	require.Eventually(t, func() bool {
		last, err = rc.Sources(ctx, &authzv3.SourcesRequest{Since: first.GetAsOf()})
		return err == nil && last.GetAllApplied()
	}, 15*time.Second, 200*time.Millisecond, "a pull after the moment applies the source")
	assert.Equal(t, first.GetAsOf(), last.GetAsOf())
	assert.Equal(t, "aligned", last.GetSources()[0].GetState())
	var version int64
	require.NoError(t, admin.QueryRow(ctx, "SELECT version FROM "+itSchema+".be_projection WHERE projection = $1 AND record_id = $2",
		core.Accounts, dave).Scan(&version))
	assert.EqualValues(t, 2, version, "the change before the moment is applied")
	_, err = rc.Sources(ctx, &authzv3.SourcesRequest{Since: "yesterday"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	// 6.5: the books of the final state. Eve's account ended at the source; the restored database still holds her
	// grant effective (the closure had not run before T): the check ends it as the closure would.
	seg := []sdkauthz.Segment{{ResourceType: core.Records, Operation: core.OpRead, Atoms: map[string]sdkauthz.Atom{core.Holder: {Kind: "all"}},
		ReadFields: []string{"id"}, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}}}
	units := listRecords(t, w, sectest.Alice, "management_unit")
	require.Len(t, units, 1)
	root := units[0]["id"].(string)

	// chapter 14: the checks and the presence of what this member audits, the recovery tool only
	cs := recoverypb.NewCheckServiceClient(dial(t, w, restore.RecoveryTool))
	_, err = recoverypb.NewCheckServiceClient(dial(t, w, "demo/orders")).Check(ctx, &recoverypb.CheckRequest{Recovery: "r"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "%v", err)
	checked, err := cs.Check(ctx, &recoverypb.CheckRequest{Recovery: "r"})
	require.NoError(t, err)
	assert.NotEmpty(t, checked.GetResults())
	var unitRev int64
	require.NoError(t, admin.QueryRow(ctx, "SELECT revision FROM "+itSchema+".authz_record WHERE id = $1", root).Scan(&unitRev))
	present, err := cs.Present(ctx, &recoverypb.PresentRequest{Recovery: "r", Objects: []*recoverypb.ObjectRef{
		{Type: "management_unit", Id: root, Version: strconv.FormatInt(unitRev, 10)},
		{Type: "management_unit", Id: root, Version: strconv.FormatInt(unitRev+1, 10)},
		{Type: "grant", Id: ids.New().String()}, {Type: "change_plan", Id: ids.New().String()}, {Type: "account", Id: dave}}})
	require.NoError(t, err)
	var answers []string
	for _, a := range present.GetAnswers() {
		answers = append(answers, a.GetAnswer())
	}
	assert.Equal(t, []string{"present", "older", "absent", "absent", "present"}, answers)
	eveGrant := submitChange(t, w, sectest.Alice, grantReq("rs-g1", root, eve, seg), 200)["record"].(string)
	bobGrant := submitChange(t, w, sectest.Alice, grantReq("rs-g2", root, sectest.Bob, seg), 200)["record"].(string)
	require.NoError(t, e.iam.set(ctx, eve, "disabled", 2))
	require.Eventually(t, func() bool { return recordOf(t, admin, eveGrant).State == "ended" }, 15*time.Second,
		100*time.Millisecond, "the precondition: the closure ends it while running")
	_, err = admin.Exec(ctx, "UPDATE "+itSchema+".authz_record SET state = 'active', end_reason = NULL WHERE id = $1", eveGrant)
	require.NoError(t, err)

	check := func(subjects ...string) *authzv3.CheckResponse {
		t.Helper()
		out, err := rc.Check(ctx, &authzv3.CheckRequest{Recovery: "r1", ReviewSubjects: subjects})
		require.NoError(t, err)
		require.Empty(t, out.GetUnprovable())
		return out
	}
	out := check(sectest.Bob, sectest.Alice)
	assert.EqualValues(t, 1, out.GetEnded(), "eve's grant")
	assert.Equal(t, "ended", recordOf(t, admin, eveGrant).State)
	assert.Equal(t, "source_ended", recordOf(t, admin, eveGrant).EndReason)
	assert.Equal(t, []string{sectest.Bob}, out.GetClosed(), "a subject under review who is no admin is closed")
	assert.Equal(t, []string{sectest.Alice}, out.GetAdminsNotClosed(), "an authorization admin stays open")
	assert.Equal(t, "held", recordOf(t, admin, bobGrant).State, "his records held by the disposition")
	assert.Equal(t, effectpoint.StateOperational, out.GetAdminState())
	reviews := func(subject string) (n int) {
		require.NoError(t, admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".authz_disposition WHERE subject = $1 "+
			"AND origin = 'recovery_review' AND state = 'active'", subject).Scan(&n))
		return n
	}
	assert.Equal(t, 1, reviews(sectest.Bob))
	again := check(sectest.Bob)
	assert.EqualValues(t, 0, again.GetEnded(), "nothing left to move")
	assert.Equal(t, 1, reviews(sectest.Bob), "closed once")

	// 6.5: the deferred intent-only tightenings
	seal := func(target, key string) []byte {
		s, err := evidence.Seal(map[string]any{"record_type": evidence.RecordType, "schema": "1.0", "id": ids.New().String(),
			"recorder": map[string]any{"component": core.ID, "instance": "i"}, "category": "security_tightening", "phase": "intent",
			"object": map[string]any{"type": core.Records, "id": target},
			"change": map[string]any{"direction": core.Tighten, "requested_by": sectest.Alice, "change_key": key, "target": target},
			"at":     "2026-11-05T10:00:00.000000Z"})
		require.NoError(t, err)
		return s.Record
	}
	deferred := func(rec []byte) string {
		t.Helper()
		out, err := rc.ReplayDeferred(ctx, &authzv3.ReplayDeferredRequest{Record: rec, Recovery: "r1"})
		require.NoError(t, err)
		return out.GetOutcome()
	}
	carolGrant := submitChange(t, w, sectest.Alice, grantReq("rs-g3", root, carol, seg), 200)["record"].(string)
	revoke := seal(carolGrant, "rs-t3")
	assert.Equal(t, evidence.Applied, deferred(revoke), "an admin stays available: executed")
	assert.Equal(t, "ended", recordOf(t, admin, carolGrant).State)
	assert.Equal(t, evidence.AlreadyReflected, deferred(revoke))
	assert.Equal(t, evidence.Dangling, deferred(seal(ids.New().String(), "rs-t4")))
	effective, err := evidence.Seal(map[string]any{"record_type": evidence.RecordType, "schema": "1.0", "id": ids.New().String(),
		"recorder": map[string]any{"component": core.ID, "instance": "i"}, "category": "security_tightening", "phase": "effective",
		"object": map[string]any{"type": core.Records, "id": carolGrant}, "change": map[string]any{"direction": core.Tighten},
		"at": "2026-11-05T10:00:00.000000Z", "position": map[string]any{"epoch": "1.1", "commit_seq": 1}})
	require.NoError(t, err)
	_, err = rc.ReplayDeferred(ctx, &authzv3.ReplayDeferredRequest{Record: effective.Record})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "only an intent-only tightening is deferred")

	var holding string
	require.NoError(t, admin.QueryRow(ctx, "SELECT id::text FROM "+itSchema+".authz_record WHERE record_type = 'management_holding' "+
		"AND body->>'holder' = $1 AND body->>'system_role' = 'authorization_admin' AND state = 'active'", sectest.Alice).Scan(&holding))
	last1 := seal(holding, "rs-t5")
	assert.Equal(t, restore.ReplayForReview, deferred(last1), "it would leave no admin: not executed")
	assert.Equal(t, "held", recordOf(t, admin, holding).State, "not ended: closed for review")
	assert.Equal(t, 1, reviews(sectest.Alice))
	assert.Equal(t, restore.ReplayForReview, deferred(last1), "again: still not executed, closed once")
	assert.Equal(t, 1, reviews(sectest.Alice))
	assert.Equal(t, effectpoint.StateRecoveryPending, check().GetAdminState(), "no admin available: an administrator recovery")

	// the deployment owner restores Alice (step 7-9): the owner's decision ends her review closure; Bob's stays
	r := adminrecovery.RecoveryRequest{Deployment: w.Deployment, Action: "restore", Identity: sectest.Alice, Nonce: "rs-restore",
		ExpiresAt: canon.Time(time.Now().Add(5 * time.Minute))}
	sig, err := r.Sign(recoveryPriv)
	require.NoError(t, err)
	code, body := callAs(t, "", "POST", "/api/authz/recovery", map[string]any{"request": r, "signature": sig})
	require.Equal(t, 200, code, "%v", body)
	assert.Equal(t, effectpoint.StateOperational, body["admin_state"])
	assert.Equal(t, 0, reviews(sectest.Alice), "released by the administrator recovery")
	assert.Equal(t, 1, reviews(sectest.Bob), "the other closures wait for their review")
}
