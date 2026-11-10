package employment

import (
	"context"
	"slices"
	"strings"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/projection"
	"github.com/jackc/pgx/v5"
)

// Person is one natural person as the employee source says (security 02, 08: "独立指不同的自然人"): the accounts
// linked now to the employee an account is linked to, the account itself always among them; an account linked to
// none is a person by itself. Proof says whether the source proves it now (Proven), or not (Unprovable: the source
// is not aligned, its watermark is past D_src_high, or a subject behind it is quarantined); facts last applied are
// what Accounts and Employee say either way.
type Person struct {
	Accounts []string
	Employee string // "" when the account is linked to none
	Proof    core.Proof
}

// EmployeeRef names an employee among the people Shares compares with (an operation on the employee's link).
func EmployeeRef(employee string) string { return "employee:" + employee }

// PersonOf is the person of an account. fresh: the source must prove it now (a confirmer's independence); otherwise
// the facts last applied are taken as proven (a disposition's accounts: every account known to be the person's).
func PersonOf(m *core.Base, ctx context.Context, tx db.Tx, account string, fresh bool) (Person, error) {
	p := Person{Accounts: []string{account}, Proof: core.Proven}
	if m.Employees == nil {
		return p, nil // no employee member: every account is a person by itself
	}
	type link struct{ Record, Employee, Account string }
	rows, err := tx.Query(ctx, `SELECT f2.record, f2.employee, f2.account FROM authz_employee_fact f1
		JOIN authz_employee_fact f2 ON f2.employee = f1.employee AND f2.kind = 'account_link' AND f2.state = 'active'
		WHERE f1.kind = 'account_link' AND f1.state = 'active' AND f1.account = $1 ORDER BY f2.account`, account)
	if err != nil {
		return p, err
	}
	links, err := pgx.CollectRows(rows, pgx.RowToStructByPos[link])
	if err != nil {
		return p, err
	}
	// the account's own subject is asked too: a quarantined event about it may be a link not applied yet
	asked := map[string][]string{"account:" + account: {"account:" + account}}
	for _, l := range links {
		p.Employee = l.Employee
		if !slices.Contains(p.Accounts, l.Account) {
			p.Accounts = append(p.Accounts, l.Account)
		}
		asked[l.Record] = []string{"employee:" + l.Employee, "account:" + l.Account}
	}
	if !fresh {
		return p, nil
	}
	j, err := m.Employees.JudgeMany(ctx, tx, asked, m.SrcHigh)
	if err != nil {
		return p, err
	}
	if j.Source != projection.Usable {
		p.Proof = core.Unprovable
		return p, nil
	}
	for _, jd := range j.Records {
		if jd.Verdict == projection.Unprovable {
			p.Proof = core.Unprovable
		}
	}
	return p, nil
}

// Shares judges whether a confirmer is the same natural person as one of people (accounts, or EmployeeRef of an
// employee): Proven when the facts say so (even facts the source cannot prove now: a confirmer is never counted
// independent on them), Disproven when the source proves they are not, Unprovable otherwise. fresh as PersonOf.
func Shares(m *core.Base, ctx context.Context, tx db.Tx, confirmer string, fresh bool, people ...string) (core.Proof, error) {
	p, err := PersonOf(m, ctx, tx, confirmer, fresh)
	if err != nil {
		return core.Unprovable, err
	}
	for _, x := range people {
		if x == "" {
			continue
		}
		if e, ok := strings.CutPrefix(x, "employee:"); ok && e == p.Employee || slices.Contains(p.Accounts, x) {
			return core.Proven, nil
		}
	}
	if p.Proof != core.Proven {
		return core.Unprovable, nil
	}
	return core.Disproven, nil
}
