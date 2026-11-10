//go:build integration

package itest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"testing/fstest"
	"time"

	core "github.com/brickKit/infra-authz/v3/internal/core"
	restore "github.com/brickKit/infra-authz/v3/internal/restore"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/component"
	"github.com/brickKit/be-sdk-go/v3/config"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/events"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/brickKit/be-sdk-go/v3/launcher"
	"github.com/brickKit/be-sdk-go/v3/runtime"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The stand-in employee member: it declares the stream mdm.employee the way mdm/employee does (its events' full states,
// the subjects employee:<id> and, on a link, account:<principal>), and the SDK serves the authorization member's pulls
// and reads of it.
const (
	empID         = "test/employee"
	empPort       = "29302"
	empSystem     = "localhost:29303"
	empSystemPort = 29303
	empSchema     = "authz_it_emp"
)

type employeeModule struct{ rt *runtime.Runtime }

func (*employeeModule) Routes(*httpx.Routes) error { return nil }

// hire writes an employee's state.
func (m *employeeModule) hire(ctx context.Context, id, state string, version int64) error {
	return m.send(ctx, "mdm.employee.changed.v1", id, version, map[string]any{"id": id, "legal_entity_id": ids.New().String(),
		"employee_no": "E-" + id[len(id)-4:], "name": "Someone", "state": state, "hire_date": "2026-01-05", "version": version},
		"employee:"+id)
}

// appoint writes an appointment's state.
func (m *employeeModule) appoint(ctx context.Context, id, employee, state string, version int64) error {
	return m.send(ctx, "mdm.employee.appointment.changed.v1", id, version, map[string]any{"id": id, "employee_id": employee,
		"legal_entity_id": ids.New().String(), "unit_id": ids.New().String(), "position_id": ids.New().String(),
		"start_date": "2026-01-05", "state": state, "version": version}, "employee:"+employee)
}

// link writes an account link's state, with the confirmations its change used.
func (m *employeeModule) link(ctx context.Context, id, employee, account, state, confirmation string, endConfirmation *string,
	version int64) error {
	return m.send(ctx, "mdm.employee.account_link.changed.v1", id, version, map[string]any{"id": id, "employee_id": employee,
		"account": account, "state": state, "confirmation": confirmation, "end_confirmation": endConfirmation,
		"linked_at": "2026-11-10T00:00:00Z", "version": version}, "employee:"+employee, "account:"+account)
}

func (m *employeeModule) send(ctx context.Context, typ, id string, version int64, data map[string]any, subjects ...string) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO records VALUES ($1, $2, $3)
			ON CONFLICT (id) DO UPDATE SET version = excluded.version, data = excluded.data`, id, version, raw); err != nil {
			return err
		}
		_, err := m.rt.Events.Emit(ctx, tx, core.EmployeeStream.Name, events.Event{Type: typ, RecordID: id, Version: version,
			Projection: events.Full, Data: json.RawMessage(raw), Subjects: subjects})
		return err
	})
}

func readEmployees(ctx context.Context, tx db.Tx, list []string) ([]events.ReadResult, error) {
	var out []events.ReadResult
	for _, id := range list {
		var v int64
		var raw []byte
		err := tx.QueryRow(ctx, "SELECT version, data FROM records WHERE id = $1", id).Scan(&v, &raw)
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

func pageEmployees(ctx context.Context, tx db.Tx, after string, limit int) ([]events.Record, error) {
	rows, err := tx.Query(ctx, `SELECT id, version, data FROM records WHERE id > $1 ORDER BY id COLLATE "C" LIMIT $2`, after, limit)
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

func employeeDefinition(built chan<- *employeeModule) component.Definition {
	none := map[string]sdkauthz.Dimension{}
	return component.Definition{ID: empID, Version: "3.0.0", GRPCPort: empSystemPort, Resend: "test.employee.record.resend",
		Recovery: "test.employee.record.recover",
		Migrations: fstest.MapFS{"0001_records.up.sql": {Data: []byte(
			"CREATE TABLE records (id text PRIMARY KEY, version bigint NOT NULL, data jsonb NOT NULL);")}},
		Streams: []events.Stream{{Name: core.EmployeeStream.Name, Partitions: core.EmployeeStream.Partitions,
			Watermark: &events.Watermark{Operation: "test.employee.record.pull", Pullers: []string{core.ID}},
			Records: &events.Records{Operation: "test.employee.record.read", Readers: []string{core.ID}, Read: readEmployees,
				Page: pageEmployees}}},
		Authz: &sdkauthz.Definitions{Component: empID,
			Resources: []sdkauthz.Resource{{Type: "test.employee.record", ViewOperation: "test.employee.record.read", Dimensions: none,
				Fields: map[string]sdkauthz.Field{}}},
			Operations: []sdkauthz.Operation{
				{Key: "test.employee.record.pull", ResourceType: "test.employee.record", Purpose: "read", RiskClass: "low"},
				{Key: "test.employee.record.read", ResourceType: "test.employee.record", Purpose: "read", RiskClass: "low"},
				{Key: "test.employee.record.resend", ResourceType: "test.employee.record", Purpose: "read", RiskClass: "low"},
				{Key: "test.employee.record.recover", ResourceType: "test.employee.record", Purpose: "read", RiskClass: "low"}}},
		New: func(rt *runtime.Runtime) (component.Module, error) {
			m := &employeeModule{rt: rt}
			built <- m
			return m, nil
		}}
}

// startEmployee migrates and runs the stand-in until the test ends; the module comes back to write records.
func startEmployee(t *testing.T, w *sectest.World, pgPassword, busURL string) *employeeModule {
	portFree(t, empPort, empSystem)
	env := w.Env(t, empID)
	for k, v := range map[string]string{"COMPONENT_ID": empID, "COMPONENT_VERSION": "3.0.0", "PORT": empPort,
		"STOP_DRAIN_DELAY": "0s", "PG_HOST": "localhost", "PG_DATABASE": itDB, "PG_USER": "postgres", "PG_PASSWORD": pgPassword,
		"PG_SCHEMA": empSchema, "PG_OWNER_USER": "postgres", "PG_OWNER_PASSWORD": pgPassword, "BUS_URL": busURL,
		"IMPLEMENTATION_INSTANCE": "emp-it-1"} {
		env[k] = v
	}
	var logs bytes.Buffer
	t.Cleanup(func() {
		if t.Failed() {
			t.Log("the stand-in employee member:\n" + logs.String())
		}
	})
	opts := func(args ...string) launcher.Options {
		return launcher.Options{Args: args, Stdout: &logs, Stderr: &logs,
			Env: config.Env{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }, Read: os.ReadFile}}
	}
	built := make(chan *employeeModule, 2)
	require.Equal(t, launcher.ExitOK, launcher.Run(context.Background(), employeeDefinition(built), opts("migrate")))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- launcher.Run(ctx, employeeDefinition(built), opts()) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case m := <-built:
		return m
	case <-time.After(15 * time.Second):
		t.Fatal("the stand-in employee member did not start")
	}
	return nil
}

// fact is one row of authz_employee_fact.
type fact struct {
	Kind, Employee, Account, State string
	Version                        int64
}

func factOf(t *testing.T, admin *pgx.Conn, record string) fact {
	var f fact
	err := admin.QueryRow(context.Background(), "SELECT kind, employee, coalesce(account, ''), state, version FROM "+itSchema+
		".authz_employee_fact WHERE record = $1", record).Scan(&f.Kind, &f.Employee, &f.Account, &f.State, &f.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return fact{}
	}
	require.NoError(t, err)
	return f
}

// TestTheEmployeeSource is C1's E4b: the employee member's stream is a second internal source with a watermark: its
// records reach the facts (who is linked to whom, the appointments), a change replaces the fact, and a full
// recovery's 6.4 waits for it as for the identity source.
func TestTheEmployeeSource(t *testing.T) {
	e := startE2E(t, withEmployee)
	ctx, admin, emp := e.ctx, e.admin, e.emp
	ann, a1, l1 := ids.New().String(), ids.New().String(), ids.New().String()
	require.NoError(t, emp.hire(ctx, ann, "active", 1))
	require.NoError(t, emp.appoint(ctx, a1, ann, "active", 1))
	require.NoError(t, emp.link(ctx, l1, ann, sectest.Bob, "active", ids.New().String(), nil, 1))
	require.Eventually(t, func() bool { return factOf(t, admin, l1).Version == 1 }, 15*time.Second, 100*time.Millisecond,
		"the link reaches the facts")
	assert.Equal(t, fact{Kind: "employee", Employee: ann, State: "active", Version: 1}, factOf(t, admin, ann))
	assert.Equal(t, fact{Kind: "appointment", Employee: ann, State: "active", Version: 1}, factOf(t, admin, a1))
	assert.Equal(t, fact{Kind: "account_link", Employee: ann, Account: sectest.Bob, State: "active", Version: 1}, factOf(t, admin, l1))

	// a change replaces the fact
	require.NoError(t, emp.appoint(ctx, a1, ann, "ended", 2))
	require.Eventually(t, func() bool { return factOf(t, admin, a1).State == "ended" }, 15*time.Second, 100*time.Millisecond)

	// 6.4 lists both sources and waits for both
	rc := authzv3.NewRecoveryServiceClient(dial(t, e.w, restore.RecoveryTool))
	first, err := rc.Sources(ctx, &authzv3.SourcesRequest{})
	require.NoError(t, err)
	require.Len(t, first.GetSources(), 2)
	assert.Equal(t, empID, first.GetSources()[1].GetComponent())
	assert.Equal(t, core.EmployeeStream.Name, first.GetSources()[1].GetStream())
	require.Eventually(t, func() bool {
		last, err := rc.Sources(ctx, &authzv3.SourcesRequest{Since: first.GetAsOf()})
		return err == nil && last.GetAllApplied() && last.GetSources()[1].GetApplied()
	}, 15*time.Second, 200*time.Millisecond, "a pull after the moment applies both sources")
}
