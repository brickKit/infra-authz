// Package employment is the employee member's facts as this member has applied them (security 02, 04, 08): the
// accounts linked to one employee are one person, and an appointment is a qualification records may bind. The
// projection Employees (the entry builds it when the deployment has an employee member) applies the source's records;
// its Changed hook calls Index, which keeps authz_employee_fact, and the entry reacts to what changed.
package employment

import (
	"context"
	"encoding/json"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	"github.com/brickKit/be-sdk-go/v3/db"
)

// Kinds of the employee source's records.
const (
	KindEmployee    = "employee"
	KindAppointment = "appointment"
	KindLink        = "account_link"
)

// Fact is one record of the employee source as applied: its kind, the employee it belongs to, a link's account, its
// state and version; Confirmation and EndConfirmation are a link's (the confirmations its change used).
type Fact struct {
	Record, Kind, Employee, Account, State string
	Version                                int64
	Confirmation, EndConfirmation          string
	Was                                    string // the state applied before ("": first seen)
}

// record is what the three kinds' full states carry that this member reads (mdm.employee's events).
type record struct {
	ID              string  `json:"id"`
	EmployeeID      string  `json:"employee_id"`
	PositionID      string  `json:"position_id"`
	Account         string  `json:"account"`
	State           string  `json:"state"`
	Version         int64   `json:"version"`
	Confirmation    string  `json:"confirmation"`
	EndConfirmation *string `json:"end_confirmation"`
}

// Index keeps one record's fact from the projection, in the transaction that applied it; ok false when the projection
// holds no complete state of it (nothing changes then).
func Index(m *core.Base, ctx context.Context, tx db.Tx, id string) (Fact, bool, error) {
	state, _, data, ok, err := m.Employees.Get(ctx, tx, id)
	if err != nil || !ok || state != "complete" {
		return Fact{}, false, err
	}
	var r record
	if err := json.Unmarshal(data, &r); err != nil {
		return Fact{}, false, err
	}
	f := Fact{Record: id, Employee: r.EmployeeID, Account: r.Account, State: r.State, Version: r.Version,
		Confirmation: r.Confirmation}
	switch {
	case r.Account != "":
		f.Kind = KindLink
	case r.PositionID != "":
		f.Kind = KindAppointment
	default:
		f.Kind, f.Employee = KindEmployee, id
	}
	if r.EndConfirmation != nil {
		f.EndConfirmation = *r.EndConfirmation
	}
	var account any
	if f.Account != "" {
		account = f.Account
	}
	err = tx.QueryRow(ctx, `WITH was AS (SELECT state FROM authz_employee_fact WHERE record = $1 FOR UPDATE),
		up AS (INSERT INTO authz_employee_fact (record, kind, employee, account, state, version) VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (record) DO UPDATE SET employee = excluded.employee, account = excluded.account,
				state = excluded.state, version = excluded.version)
		SELECT coalesce((SELECT state FROM was), '')`, id, f.Kind, f.Employee, account, f.State, f.Version).Scan(&f.Was)
	return f, true, err
}
