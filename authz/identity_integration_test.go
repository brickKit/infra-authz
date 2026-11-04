//go:build integration

package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
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
	rec := map[string]any{
		"record_type": "be.security.account_status", "schema": "1.0", "deployment": m.rt.Config.String("DEPLOYMENT_ID"),
		"authority": iamID, "id": principal,
		"revision": map[string]any{"domain": AccountStream.Name, "value": strconv.FormatInt(version, 10)},
		"account":  map[string]any{"deployment": m.rt.Config.String("DEPLOYMENT_ID"), "kind": "user", "id": principal},
		"status":   status, "security_version": version}
	if mark != "" {
		rec["security_mark"] = mark
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
	return component.Definition{ID: iamID, Version: "3.0.0", GRPCPort: iamSystemPort,
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
				{Key: "test.iam.account.read", ResourceType: "test.iam.account", Purpose: "read", RiskClass: "low"}}},
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
