package employment

import (
	"context"
	"encoding/json"
	"errors"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/projection"
	"github.com/jackc/pgx/v5"
)

// Bindings of a record to an appointment (security 04, D30): a grant or a management holding may name an appointment;
// it counts while the appointment is active and its account is linked to the appointment's employee. The appointment
// is a qualification instance that is never reused (a transfer ends it and makes another), so its end ends what is
// bound to it: the view leaves the record out at once, the closure books it ended (source_ended).

// Binding is one record's appointment and account.
type Binding struct{ Appointment, Account string }

// bindingFact is what the facts last applied say of a binding: the appointment's state and employee, and whether the
// account's link to that employee is active (with the link's record, to judge it).
type bindingFact struct {
	State, Employee, Link string
	Known                 bool
}

func factOfBinding(ctx context.Context, tx db.Tx, b Binding) (bindingFact, error) {
	var f bindingFact
	err := tx.QueryRow(ctx, `SELECT a.state, a.employee, coalesce((SELECT l.record FROM authz_employee_fact l
			WHERE l.kind = 'account_link' AND l.state = 'active' AND l.employee = a.employee AND l.account = $2 LIMIT 1), '')
		FROM authz_employee_fact a WHERE a.record = $1 AND a.kind = 'appointment'`, b.Appointment, b.Account).
		Scan(&f.State, &f.Employee, &f.Link)
	if errors.Is(err, pgx.ErrNoRows) {
		return f, nil
	}
	f.Known = err == nil
	return f, err
}

// Grantable judges a new binding when a record is made (the effect point, at D_src_high): Proven when the appointment
// is planned or active and the account linked to its employee, Disproven (with why) when the source proves otherwise,
// Unprovable when it cannot prove either now.
func Grantable(m *core.Base, ctx context.Context, tx db.Tx, b Binding) (core.Proof, string, error) {
	if m.Employees == nil {
		return core.Disproven, "the deployment has no employee member: nothing binds an appointment", nil
	}
	f, err := factOfBinding(ctx, tx, b)
	if err != nil {
		return core.Unprovable, "", err
	}
	asked := map[string][]string{b.Appointment: {"employee:" + f.Employee}, "account:" + b.Account: {"account:" + b.Account}}
	if f.Link != "" {
		asked[f.Link] = []string{"employee:" + f.Employee, "account:" + b.Account}
	}
	j, err := m.Employees.JudgeMany(ctx, tx, asked, m.SrcHigh)
	if err != nil {
		return core.Unprovable, "", err
	}
	for _, jd := range j.Records {
		if jd.Verdict == projection.Unprovable {
			return core.Unprovable, "the employee source cannot prove the appointment and the link now", nil
		}
	}
	switch {
	case !f.Known:
		return core.Disproven, "no appointment " + b.Appointment, nil
	case f.State != "planned" && f.State != "active":
		return core.Disproven, "the appointment " + b.Appointment + " is " + f.State, nil
	case f.Link == "":
		return core.Disproven, "the account is not linked to the appointment's employee", nil
	}
	return core.Proven, "", nil
}

// Effective answers which bindings give access now (a view, at within): the appointment active and the link active,
// both usable in the source; anything else, unprovable included, gives nothing (no access without evidence).
func Effective(m *core.Base, ctx context.Context, tx db.Tx, bindings []Binding) (map[Binding]bool, error) {
	out := map[Binding]bool{}
	if m.Employees == nil || len(bindings) == 0 {
		return out, nil
	}
	facts := map[Binding]bindingFact{}
	asked := map[string][]string{}
	for _, b := range bindings {
		f, err := factOfBinding(ctx, tx, b)
		if err != nil {
			return nil, err
		}
		if !f.Known || f.Link == "" {
			continue
		}
		facts[b] = f
		asked[b.Appointment] = []string{"employee:" + f.Employee}
		asked[f.Link] = []string{"employee:" + f.Employee, "account:" + b.Account}
	}
	if len(asked) == 0 {
		return out, nil
	}
	j, err := m.Employees.JudgeMany(ctx, tx, asked, m.SrcRead)
	if err != nil {
		return nil, err
	}
	state := func(id string) string {
		jd := j.Records[id]
		if jd.Verdict != projection.Usable {
			return ""
		}
		var r struct {
			State string `json:"state"`
		}
		_ = json.Unmarshal(jd.Data, &r)
		return r.State
	}
	for b, f := range facts {
		out[b] = state(b.Appointment) == "active" && state(f.Link) == "active"
	}
	return out, nil
}

// HeldApplied: a binding counts by the facts last applied (a management holding's availability between the source's
// change and the closure: the appointment active, the link active).
func HeldApplied(ctx context.Context, tx db.Tx, b Binding) (bool, error) {
	f, err := factOfBinding(ctx, tx, b)
	return f.Known && f.State == "active" && f.Link != "", err
}

// Ended judges a binding for the closure (at D_src_high): ended when the source proves the appointment ended or the
// account no longer linked to its employee; provable false when it cannot prove it now.
func Ended(m *core.Base, ctx context.Context, tx db.Tx, b Binding) (ended, provable bool, err error) {
	if m.Employees == nil {
		return false, true, nil
	}
	f, err := factOfBinding(ctx, tx, b)
	if err != nil {
		return false, false, err
	}
	asked := map[string][]string{b.Appointment: {"employee:" + f.Employee}, "account:" + b.Account: {"account:" + b.Account}}
	if f.Link != "" {
		asked[f.Link] = []string{"employee:" + f.Employee, "account:" + b.Account}
	}
	j, err := m.Employees.JudgeMany(ctx, tx, asked, m.SrcHigh)
	if err != nil {
		return false, false, err
	}
	for _, jd := range j.Records {
		if jd.Verdict == projection.Unprovable {
			return false, false, nil
		}
	}
	return !f.Known || f.State == "ended" || f.Link == "", true, nil
}

// AppointmentsOf are the appointments of an employee (an ended link closes what its account holds through them).
func AppointmentsOf(ctx context.Context, tx db.Tx, employee string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT record FROM authz_employee_fact WHERE kind = 'appointment' AND employee = $1 ORDER BY record`,
		employee)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// Closures registers the closure of what a change binds (security 04's "原任职结束"): an appointment whose state
// moved, or every appointment of an employee whose link to an account ended (the account's bindings through them).
// close is the effect point's CloseAfter (this package is below it).
func Closures(m *core.Base, ctx context.Context, tx db.Tx, f Fact,
	close func(m *core.Base, ctx context.Context, tx db.Tx, kind, ref string) error) error {
	switch {
	case f.Kind == KindAppointment && f.State != f.Was && f.Was != "":
		return close(m, ctx, tx, "appointment", f.Record)
	case f.Kind == KindLink && f.State == "ended" && f.Was != "ended":
		list, err := AppointmentsOf(ctx, tx, f.Employee)
		if err != nil {
			return err
		}
		for _, a := range list {
			if err := close(m, ctx, tx, "appointment", a); err != nil {
				return err
			}
		}
	}
	return nil
}
