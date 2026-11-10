package accounts

import (
	"context"
	"errors"
	"strconv"
	"time"

	core "github.com/brickKit/infra-authz/v3/internal/core"
	effectpoint "github.com/brickKit/infra-authz/v3/internal/effectpoint"
	employment "github.com/brickKit/infra-authz/v3/internal/employment"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/ids"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/jackc/pgx/v5"
)

// Account links (security 08 row 21, "确认与受保护操作" item 3; security 02): the link of an account to an employee
// and its end are protected operations of the employee member, confirmed here:
//   - a confirmation binds the employee, the account, the action (link, unlink) and the employee's version;
//   - the employee member asks CheckLinkChange before the change, with the confirmation; nothing is used then;
//   - the link record carrying it (its confirmation, or its end_confirmation) uses it when this member applies it
//     from the employee member's stream; a link applied without a valid one is a source fact: it stands, and alerts.
//
// A link widens (it decides which account an appointment's grants reach, and who is the same person): the owner
// stands in only when no other admin is available. Its end tightens: the owner stands in at any time.

const (
	actionLink   = "link"
	actionUnlink = "unlink"
)

// MaxAdministratorsAsked bounds one Administrators call (contract-infra-authz alpha.6).
const MaxAdministratorsAsked = 100

// linkBinding is what an owner signs for a link's change: the employee, and the action on the account at the
// employee's version.
func linkBinding(m *core.Base, employee, account, action string, version int64, until time.Time) sdkauthz.OwnerConfirmation {
	return sdkauthz.OwnerConfirmation{Deployment: m.Deployment, Target: employee,
		ExpectedRevision: action + ":" + account + "@" + strconv.FormatInt(version, 10), ExpiresAt: canon.Time(until)}
}

func linkArgs(employee, account, action string, version int64) error {
	if !core.UUIDText.MatchString(employee) || !core.UUIDText.MatchString(account) || (action != actionLink && action != actionUnlink) ||
		version < 1 {
		return errs.New(errs.ReasonRequestInvalid, "a link's confirmation names the employee, the account, the action (link or "+
			"unlink) and the employee_version")
	}
	return nil
}

// ConfirmLink records a confirmation of a link's change (holding, or the owner's signature).
func ConfirmLink(m *core.Base, ctx context.Context, tx db.Tx, confirmer string, in effectpoint.ConfirmIn) (string, time.Time, error) {
	var version int64
	if in.EmployeeVersion != nil {
		version = *in.EmployeeVersion
	}
	if err := linkArgs(in.Employee, in.Account, in.Action, version); err != nil {
		return "", time.Time{}, err
	}
	if confirmer == in.Account {
		return "", time.Time{}, errs.New(errs.ReasonPermissionDenied, "nobody confirms a link of their own account")
	}
	admin, err := administrator(ctx, tx, in.Account)
	if err != nil {
		return "", time.Time{}, err
	}
	until := time.Now().Add(effectpoint.ConfirmationValidity)
	// the end of a link of an account that is no admin may be confirmed on the last applied facts (row 22's exemption)
	basis, who, until, err := effectpoint.ConfirmerBasis(m, ctx, tx, confirmer, in,
		linkBinding(m, in.Employee, in.Account, in.Action, version, until), until, !admin && in.Action == actionUnlink)
	if err != nil {
		return "", time.Time{}, err
	}
	id := ids.New().String()
	_, err = tx.Exec(ctx, `INSERT INTO authz_confirmation (id, account, employee, link_action, employee_version, confirmer, basis,
		expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, id, in.Account, in.Employee, in.Action, version, who, basis, until)
	return id, until, err
}

// CheckLinkChange is AccountService.CheckLinkChange (contract-infra-authz alpha.6): it checks, it uses nothing.
func CheckLinkChange(m *core.Base, ctx context.Context, in *authzv3.CheckLinkChangeRequest) (*authzv3.CheckLinkChangeResponse, error) {
	if err := linkArgs(in.GetEmployee(), in.GetAccount(), in.GetAction(), in.GetEmployeeVersion()); err != nil {
		return nil, err
	}
	if !core.UUIDText.MatchString(in.GetRequester()) {
		return nil, errs.New(errs.ReasonRequestInvalid, "requester is required")
	}
	out := &authzv3.CheckLinkChangeResponse{}
	err := m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		out.Verdict, out.Reason, err = linkVerdict(m, ctx, tx, in)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func linkVerdict(m *core.Base, ctx context.Context, tx db.Tx, in *authzv3.CheckLinkChangeRequest) (authzv3.AccountChangeVerdict, string, error) {
	if in.GetConfirmation() == "" {
		return authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_CONFIRMATION_REQUIRED, "protected: an account's link to an employee", nil
	}
	refused := func(why string) (authzv3.AccountChangeVerdict, string, error) {
		return authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_REFUSED, why, nil
	}
	var c accountConfirmation
	err := tx.QueryRow(ctx, `SELECT confirmer, basis, consumed_by_change IS NULL AND expires_at > now() FROM authz_confirmation
		WHERE id::text = $1 AND employee = $2 AND account = $3 AND link_action = $4 AND employee_version = $5`,
		in.GetConfirmation(), in.GetEmployee(), in.GetAccount(), in.GetAction(), in.GetEmployeeVersion()).Scan(&c.confirmer, &c.basis, &c.usable)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return refused("the confirmation does not bind this employee, account, action and version")
	case err != nil:
		return 0, "", err
	case !c.usable:
		return refused("the confirmation is used or expired")
	case c.confirmer == in.GetRequester() || c.confirmer == in.GetAccount():
		return refused("the confirmer is the requester or the account itself")
	}
	unlink := in.GetAction() == actionUnlink
	if c.basis == effectpoint.BasisOwner {
		if unlink {
			return authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_ALLOWED, "", nil // a tightening: the owner stands in
		}
		switch others, err := effectpoint.OthersAvailable(m, ctx, tx, in.GetRequester(), in.GetAccount()); {
		case err != nil:
			return 0, "", err
		case others:
			return refused("another authorization admin is available: the owner does not stand in for a link")
		}
		return authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_ALLOWED, "", nil
	}
	admin, err := administrator(ctx, tx, in.GetAccount())
	if err != nil {
		return 0, "", err
	}
	switch ok, err := effectpoint.ConfirmerEligible(m, ctx, tx, c.confirmer, !admin && unlink); {
	case err != nil:
		return 0, "", err
	case ok == core.Unprovable:
		return authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_UNPROVABLE, "the confirmer's eligibility cannot be proven now", nil
	case ok != core.Proven:
		return refused("the confirmer is not a qualified authorization admin now")
	}
	return authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_ALLOWED, "", nil
}

// Administrators is AccountService.Administrators: those of the accounts holding the authorization admin role now.
func Administrators(m *core.Base, ctx context.Context, in *authzv3.AdministratorsRequest) (*authzv3.AdministratorsResponse, error) {
	if len(in.GetAccounts()) > MaxAdministratorsAsked {
		return nil, errs.New(errs.ReasonRequestInvalid, "at most "+strconv.Itoa(MaxAdministratorsAsked)+" accounts")
	}
	out := &authzv3.AdministratorsResponse{}
	err := m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT body->>'holder' FROM authz_record WHERE state IN ('active', 'held')
			AND record_type = 'management_holding' AND body->>'system_role' = 'authorization_admin' AND body->>'holder' = ANY($1)
			ORDER BY 1`, in.GetAccounts())
		if err != nil {
			return err
		}
		out.Administrators, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// LinkChanged is the employee source's Changed hook's part for a link: a link applied uses its confirmation, an end
// applied its end confirmation (marked used by "link:<link>@<version>", "unlink:<link>@<version>"). One that does not
// hold leaves the link standing (a source fact) and alerts.
func LinkChanged(m *core.Base, ctx context.Context, tx db.Tx, f employment.Fact) error {
	if f.Kind != employment.KindLink {
		return nil
	}
	use := func(action, confirmation string) error {
		change := action + ":" + f.Record + "@" + strconv.FormatInt(f.Version, 10)
		tag, err := tx.Exec(ctx, `UPDATE authz_confirmation SET consumed_by_change = $5 WHERE id::text = $1 AND employee = $2
			AND account = $3 AND link_action = $4 AND consumed_by_change IS NULL`, confirmation, f.Employee, f.Account, action, change)
		if err != nil || tag.RowsAffected() == 1 {
			return err
		}
		m.RT.Logger.Error("an account link changed without a valid confirmation: it stands (a source fact)",
			"event", "account_link_unconfirmed", "link", f.Record, "employee", f.Employee, "account", f.Account, "action", action,
			"confirmation", confirmation)
		return nil
	}
	if f.Was == "" { // first seen: the link was made (whatever it is now)
		if err := use(actionLink, f.Confirmation); err != nil {
			return err
		}
	}
	if f.State == "ended" && f.Was != "ended" {
		return use(actionUnlink, f.EndConfirmation)
	}
	return nil
}

// LinkPayloadHTTP answers what the deployment owner signs for a link's change.
func LinkPayloadHTTP(m *core.Base, c *httpx.Context, employee string) error {
	action := c.Query("action")
	op := core.OpChange
	if action == actionUnlink {
		op = core.OpTighten
	}
	s, _ := sdkauthz.From(c.Ctx())
	if _, _, err := s.Check(c.Ctx(), op, sdkauthz.Facts{}); err != nil {
		return err
	}
	version, err := strconv.ParseInt(c.Query("employee_version"), 10, 64)
	if err != nil {
		return errs.New(errs.ReasonRequestInvalid, "employee_version is an integer")
	}
	if err := linkArgs(employee, c.Query("account"), action, version); err != nil {
		return err
	}
	o := linkBinding(m, employee, c.Query("account"), action, version, time.Now().Add(effectpoint.ConfirmationValidity))
	return c.JSON(200, map[string]any{"deployment": o.Deployment, "target": o.Target, "expires_at": o.ExpiresAt,
		"expected_revision": o.ExpectedRevision})
}
