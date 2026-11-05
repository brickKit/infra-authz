//go:build integration

package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/component"
	"github.com/brickKit/be-sdk-go/v3/config"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/events"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/launcher"
	"github.com/brickKit/be-sdk-go/v3/records"
	"github.com/brickKit/be-sdk-go/v3/runtime"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The stand-in identity member: components never import each other's code (decision 0101), so the test declares the
// account status stream the way every identity member does (contract-infra-iam), and the SDK serves the
// authorization member's pulls and reads of it.
const (
	iamID         = "test/iam"
	iamPort       = "29300"
	iamSystem     = "localhost:29301"
	iamSystemPort = 29301
	iamSchema     = "authz_it_iam"
)

type iamModule struct{ rt *runtime.Runtime }

func (*iamModule) Routes(*httpx.Routes) error { return nil }

// set writes an account's status and sends it, as an identity member does on a security change (P8.27).
func (m *iamModule) set(ctx context.Context, principal, status string, version int64) error {
	return m.setMarked(ctx, principal, status, "", version)
}

// setMarked is set with a security mark (compromised, suspicious; security 09a).
func (m *iamModule) setMarked(ctx context.Context, principal, status, mark string, version int64) error {
	return m.send(ctx, principal, status, mark, "", version)
}

// setConfirmed is set carrying the confirmation the change used (09a's confirmation; T9d).
func (m *iamModule) setConfirmed(ctx context.Context, principal, status, confirmation string, version int64) error {
	return m.send(ctx, principal, status, "", confirmation, version)
}

func (m *iamModule) send(ctx context.Context, principal, status, mark, confirmation string, version int64) error {
	rec := map[string]any{
		"record_type": "be.security.account_status", "schema": "1.0", "deployment": m.rt.Config.String("DEPLOYMENT_ID"),
		"authority": iamID, "id": principal,
		"revision": map[string]any{"domain": AccountStream.Name, "value": strconv.FormatInt(version, 10)},
		"account":  map[string]any{"deployment": m.rt.Config.String("DEPLOYMENT_ID"), "kind": "user", "id": principal},
		"status":   status, "security_version": version}
	if mark != "" {
		rec["security_mark"] = mark
	}
	if confirmation != "" {
		rec["confirmation"] = confirmation
	}
	raw, _, err := records.Seal("be.security.account_status", rec)
	if err != nil {
		return err
	}
	return m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO accounts VALUES ($1, $2, $3)
			ON CONFLICT (principal) DO UPDATE SET version = excluded.version, record = excluded.record`, principal, version, raw); err != nil {
			return err
		}
		_, err := m.rt.Events.Emit(ctx, tx, AccountStream.Name, events.Event{Type: "infra.iam.account_status_changed.v1",
			RecordID: principal, Version: version, Projection: events.Full, Data: json.RawMessage(raw), Subjects: []string{principal}})
		return err
	})
}

func readIAM(ctx context.Context, tx db.Tx, ids []string) ([]events.ReadResult, error) {
	var out []events.ReadResult
	for _, id := range ids {
		var v int64
		var raw []byte
		err := tx.QueryRow(ctx, "SELECT version, record FROM accounts WHERE principal = $1", id).Scan(&v, &raw)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			out = append(out, events.ReadResult{ID: id, State: events.Purged})
		case err != nil:
			return nil, err
		default:
			out = append(out, events.ReadResult{ID: id, State: events.Exists, Version: v, Data: json.RawMessage(raw)})
		}
	}
	return out, nil
}

func pageIAM(ctx context.Context, tx db.Tx, after string, limit int) ([]events.Record, error) {
	rows, err := tx.Query(ctx, `SELECT principal, version, record FROM accounts WHERE principal > $1
		ORDER BY principal COLLATE "C" LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []events.Record
	for rows.Next() {
		var r events.Record
		var raw []byte
		if err := rows.Scan(&r.ID, &r.Version, &raw); err != nil {
			return nil, err
		}
		r.Data = json.RawMessage(raw)
		out = append(out, r)
	}
	return out, rows.Err()
}

func iamDefinition(built chan<- *iamModule) component.Definition {
	none := map[string]sdkauthz.Dimension{}
	return component.Definition{ID: iamID, Version: "3.0.0", GRPCPort: iamSystemPort, Resend: "test.iam.account.resend",
		Migrations: fstest.MapFS{"0001_accounts.up.sql": {Data: []byte(
			"CREATE TABLE accounts (principal text PRIMARY KEY, version bigint NOT NULL, record bytea NOT NULL);")}},
		Streams: []events.Stream{{Name: AccountStream.Name, Partitions: AccountStream.Partitions,
			Watermark: &events.Watermark{Operation: "test.iam.account.pull", Pullers: []string{ID}},
			Records:   &events.Records{Operation: "test.iam.account.read", Readers: []string{ID}, Read: readIAM, Page: pageIAM}}},
		Authz: &sdkauthz.Definitions{Component: iamID,
			Resources: []sdkauthz.Resource{{Type: "test.iam.account", ViewOperation: "test.iam.account.read", Dimensions: none,
				Fields: map[string]sdkauthz.Field{}}},
			Operations: []sdkauthz.Operation{
				{Key: "test.iam.account.pull", ResourceType: "test.iam.account", Purpose: "read", RiskClass: "low"},
				{Key: "test.iam.account.read", ResourceType: "test.iam.account", Purpose: "read", RiskClass: "low"},
				{Key: "test.iam.account.resend", ResourceType: "test.iam.account", Purpose: "read", RiskClass: "low"}}},
		New: func(rt *runtime.Runtime) (component.Module, error) {
			m := &iamModule{rt: rt}
			built <- m
			return m, nil
		}}
}

// startIAM migrates and runs the stand-in until the returned stop is called; the module comes back to set accounts.
func startIAM(t *testing.T, w *sectest.World, pgPassword, busURL string, fresh bool) (*iamModule, func()) {
	portFree(t, iamPort, iamSystem)
	env := w.Env(t, iamID)
	for k, v := range map[string]string{"COMPONENT_ID": iamID, "COMPONENT_VERSION": "3.0.0", "PORT": iamPort,
		"STOP_DRAIN_DELAY": "0s", "PG_HOST": "localhost", "PG_DATABASE": itDB, "PG_USER": "postgres", "PG_PASSWORD": pgPassword,
		"PG_SCHEMA": iamSchema, "PG_OWNER_USER": "postgres", "PG_OWNER_PASSWORD": pgPassword, "BUS_URL": busURL,
		"IMPLEMENTATION_INSTANCE": "iam-it-1"} {
		env[k] = v
	}
	var logs bytes.Buffer
	t.Cleanup(func() {
		if t.Failed() {
			t.Log("the stand-in identity member:\n" + logs.String())
		}
	})
	opts := func(args ...string) launcher.Options {
		return launcher.Options{Args: args, Stdout: &logs, Stderr: &logs,
			Env: config.Env{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }, Read: os.ReadFile}}
	}
	built := make(chan *iamModule, 2)
	if fresh {
		require.Equal(t, launcher.ExitOK, launcher.Run(context.Background(), iamDefinition(built), opts("migrate")))
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- launcher.Run(ctx, iamDefinition(built), opts()) }()
	var m *iamModule
	select {
	case m = <-built:
	case <-time.After(15 * time.Second):
		t.Fatal("the stand-in identity member did not start")
	}
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			cancel()
			<-done
		}
	}
	t.Cleanup(stop)
	return m, stop
}

// identity is T3: the identity member's account status in the views, stale tokens, the source going quiet.
func (e *e2e) identity() {
	t, w, admin, ctx, verify, held, root, eastID := e.t, e.w, e.admin, e.ctx, e.verify, e.held, e.root, e.east
	iam, stopIAM, pgPassword, busURL := e.iam, e.stopIAM, e.pgPassword, e.busURL
	defer func() { e.held = held }()
	var code int
	var out map[string]any
	// T3: the identity member's account status reaches the views (security 03's internal sources; P8.25)
	again4 := submitChange(t, w, sectest.Alice, grantReq("b4", root, carol, []sdkauthz.Segment{orderSeg(region("east"))}), 200)
	require.NotEmpty(t, again4["record"])
	carolNow := func(want func(sdkauthz.SubjectEntry) bool) sdkauthz.SubjectEntry {
		var e sdkauthz.SubjectEntry
		require.Eventually(t, func() bool {
			ans := verify(held)
			if ans.Shards[0].Status == "changed" {
				held.Digest, e = ans.Shards[0].View.Digest, ans.Shards[0].View.Subjects[carol]
			}
			return want(e)
		}, 10*time.Second, 200*time.Millisecond)
		return e
	}
	entry := carolNow(func(e sdkauthz.SubjectEntry) bool { return len(e.Segments) > 0 })
	assert.EqualValues(t, 1, entry.SecurityVersion, "the account's security version is in the view")
	assert.False(t, entry.AccountsDisabled)
	require.NoError(t, iam.set(ctx, carol, "active", 2)) // a password change at the identity member
	carolNow(func(e sdkauthz.SubjectEntry) bool { return e.SecurityVersion == 2 })
	// frozen: an identity-side disposition (T6c) holds her grant and leaves her segments out; nothing ends
	require.NoError(t, iam.set(ctx, carol, "security_frozen", 3))
	require.Eventually(t, func() bool { return recordOf(t, admin, again4["record"]).State == "held" }, 10*time.Second,
		100*time.Millisecond, "held by the identity-side disposition")
	carolNow(func(e sdkauthz.SubjectEntry) bool { return len(e.Segments) == 0 })

	// disabled: the account ended as a source; the closure job ends what it was a source of (security 08), a grant
	// and a holding, once its status is applied
	daves := submitChange(t, w, sectest.Alice, grantReq("dv1", root, dave, []sdkauthz.Segment{orderSeg(region("east"))}), 200)
	daveHolds := protectBy(t, w, sectest.Alice, sectest.Bob, holdingReq("dv2", eastID, dave)) // Bob is an admin again
	eves := submitChange(t, w, sectest.Alice, grantReq("dv3", root, eve, []sdkauthz.Segment{orderSeg(region("east"))}), 200)
	require.NoError(t, iam.setMarked(ctx, eve, "disabled", "compromised", 2)) // a disposition (T6), not the source's end
	require.NoError(t, iam.set(ctx, dave, "disabled", 2))
	require.Eventually(t, func() bool {
		return recordOf(t, admin, daves["record"]).State == "ended" && recordOf(t, admin, daveHolds["record"]).State == "ended"
	}, 10*time.Second, 100*time.Millisecond, "the books of a disabled account")
	assert.Equal(t, "source_ended", recordOf(t, admin, daves["record"]).EndReason)
	assert.Equal(t, "source_ended", recordOf(t, admin, daveHolds["record"]).EndReason)
	assert.Equal(t, "held", recordOf(t, admin, again4["record"]).State, "carol is frozen, not disabled: her grant is held, not ended")
	require.Eventually(t, func() bool { // two statuses applied (her first, then disabled): two closures, both done
		var all, done int
		_ = admin.QueryRow(ctx, "SELECT count(*), count(*) FILTER (WHERE state = 'done') FROM "+itSchema+
			".be_work_item WHERE job = $1 AND args->>'ref' = $2", JobClosure, eve).Scan(&all, &done)
		return all >= 2 && done == all
	}, 10*time.Second, 100*time.Millisecond, "eve's closures ran")
	assert.Equal(t, "held", recordOf(t, admin, eves["record"]).State, "disabled as compromised: a disposition holds it, nothing ends")

	// Bob's security change: tokens issued before are stale at the member's own surface; one of the new version passes
	require.NoError(t, iam.set(ctx, sectest.Bob, "active", 2))
	require.Eventually(t, func() bool {
		code, out := callAs(t, "Bearer "+w.TokenAt(sectest.Bob, 1), "GET", "/api/authz/records?type=grant", nil)
		return code == 401 && out["reason"] == "TOKEN_STALE"
	}, 10*time.Second, 200*time.Millisecond, "TOKEN_STALE once the member's own view has the new version")
	code, out = callAs(t, "Bearer "+w.TokenAt(sectest.Bob, 2), "GET", "/api/authz/records?type=grant", nil)
	assert.Equal(t, 200, code, "%v", out)

	// the identity member goes quiet: past D_src_high (3 s) the views renew for ordinary reads only, past D_src_read
	// (6 s) they close; once it answers again they renew fully (security 03's renewal and closing, P8.11). A grant
	// due meanwhile cannot prove its requester (row 9): the job waits, its attempt not counted, and takes effect once
	// the source answers again (CP41, CP68)
	waiting := submitChange(t, w, sectest.Alice, scheduledGrant("d5", root, sectest.Bob, []sdkauthz.Segment{orderSeg(region("east"))},
		4*time.Second), 202)
	stopIAM()
	status := func() (string, bool) {
		ans := verify(held)
		if ans.Shards[0].Status == "changed" {
			held.Digest = ans.Shards[0].View.Digest
		}
		return ans.Shards[0].Status, ans.Shards[0].ReadOnly
	}
	st, ro := status()
	require.True(t, st != "closed" && !ro, "the precondition: a fresh source renews fully (%s, read-only %v)", st, ro)
	require.Eventually(t, func() bool { st, ro := status(); return st != "closed" && ro }, 10*time.Second, 200*time.Millisecond,
		"ordinary reads only")
	require.Eventually(t, func() bool { st, _ := status(); return st == "closed" }, 10*time.Second, 200*time.Millisecond,
		"closed")
	require.Eventually(t, func() bool {
		d := dueItemOf(t, admin, waiting["record"])
		return d.State == "retry_wait" && d.Attempts == 0 && strings.Contains(d.LastError, "ADMIN_AVAILABILITY_UNPROVABLE")
	}, 5*time.Second, 50*time.Millisecond, "due while the source is quiet: processing, a wait that spends no attempt")
	assert.Equal(t, "scheduled", recordOf(t, admin, waiting["record"]).State, "no access while it waits")
	// a user's widening meanwhile (CP37): the requester cannot be proven, so it is retried later, nothing applied,
	// the key not bound. Which answer depends on time: the effect point's processing (row 9, 202) while the member's
	// own view still admits high-risk operations, or admission's AUTHORIZATION_VIEW_EXPIRED (503) once it does not
	// (security 03: high-risk validity runs from the last full renewal)
	cp37 := grantReq("cp37", root, sectest.Bob, []sdkauthz.Segment{orderSeg(region("west"))})
	code, out = call(t, w, sectest.Alice, "POST", "/api/authz/changes", cp37)
	assert.True(t, code == 202 && out["outcome"] == "processing" && out["reason"] == "ADMIN_AVAILABILITY_UNPROVABLE" ||
		code == 503 && out["reason"] == "AUTHORIZATION_VIEW_EXPIRED", "%d %v", code, out)
	var bound int
	require.NoError(t, admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".authz_change WHERE requested_by = $1 AND change_key = 'cp37'",
		sectest.Alice).Scan(&bound))
	assert.Zero(t, bound, "nothing binds the key: submit again with the same key")
	assert.Empty(t, derivedBinding(t, admin, waiting["record"], 1, triggerScheduled), "processing binds nothing")
	_, stopIAM = startIAM(t, w, pgPassword, busURL, false)
	require.Eventually(t, func() bool { st, ro := status(); return st != "closed" && !ro }, 15*time.Second, 200*time.Millisecond,
		"renewed fully again")
	require.Eventually(t, func() bool { return recordOf(t, admin, waiting["record"]).State == "active" }, 10*time.Second,
		100*time.Millisecond, "the source answers again: the waiting job takes effect")
	assert.Equal(t, "applied", derivedBinding(t, admin, waiting["record"], 1, triggerScheduled))
	require.Eventually(t, func() bool { // the member's own view renews fully at its next verification
		code, out := call(t, w, sectest.Alice, "POST", "/api/authz/changes", cp37)
		return code == 200 && out["outcome"] == "applied"
	}, 10*time.Second, 200*time.Millisecond, "the same key, once the source answers")
	stopIAM()

}
