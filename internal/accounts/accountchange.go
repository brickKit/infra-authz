package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	core "github.com/brickKit/infra-authz/v3/internal/core"
	effectpoint "github.com/brickKit/infra-authz/v3/internal/effectpoint"

	"github.com/brickKit/be-sdk-go/v3/audit"
	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/identity"
	"github.com/brickKit/be-sdk-go/v3/ids"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/jackc/pgx/v5"
)

// Account status changes (security 08, "管理员账号的状态变更"; security 03's two-person rule beyond T_tight; A134):
//   - a confirmation can bind an account, the status it takes and the security version the change is made on;
//   - the identity member asks CheckAccountChange before it changes a status: a confirmation is needed when the
//     account holds the authorization admin role (a protected operation) or its own basis is stale beyond T_tight;
//   - the account status that carries the confirmation uses it when this member applies it; an admin account
//     re-enabled or unfrozen without a valid one has its admin holdings marked confirmation_backfill_pending (09a:
//     unavailable, an error log) until a protected reconfirmation; one disabled or frozen without one takes effect and
//     alerts.

var accountStates = map[string]bool{"active": true, "disabled": true, "security_frozen": true}

// accountBinding is what an owner signs for an account's status change: the account, and the status at a version.
func accountBinding(m *core.Base, account, state string, version int64, until time.Time) sdkauthz.OwnerConfirmation {
	return sdkauthz.OwnerConfirmation{Deployment: m.Deployment, Target: account,
		ExpectedRevision: state + "@" + strconv.FormatInt(version, 10), ExpiresAt: canon.Time(until)}
}

// projectedVersion is the account's security version as this member has applied it (0: none).
func projectedVersion(m *core.Base, ctx context.Context, tx db.Tx, account string) (int64, error) {
	state, _, data, ok, err := m.Accounts.Get(ctx, tx, account)
	if err != nil || !ok || state != "complete" {
		return 0, err
	}
	var rec struct {
		Version int64 `json:"security_version"`
	}
	return rec.Version, json.Unmarshal(data, &rec)
}

// ConfirmAccount records a confirmation of an account's status change (holding, or the owner's signature).
func ConfirmAccount(m *core.Base, ctx context.Context, tx db.Tx, confirmer string, in effectpoint.ConfirmIn) (string, time.Time, error) {
	if !core.UUIDText.MatchString(in.Account) || !accountStates[in.TargetState] {
		return "", time.Time{}, errs.New(errs.ReasonRequestInvalid, "an account's confirmation names the account and its target_state")
	}
	if ok, err := effectpoint.Independent(m, ctx, tx, confirmer, false, in.Account); err != nil || ok == core.Disproven {
		if err != nil {
			return "", time.Time{}, err
		}
		return "", time.Time{}, errs.New(errs.ReasonPermissionDenied, "nobody confirms a change of their own account (one person)")
	}
	version, err := projectedVersion(m, ctx, tx, in.Account)
	if err != nil {
		return "", time.Time{}, err
	}
	if in.TargetStateVersion != nil {
		version = *in.TargetStateVersion
	}
	if version < 1 {
		return "", time.Time{}, errs.New(errs.ReasonRequestInvalid, "no status of this account is known: name target_state_version")
	}
	// row 22's exemption, as when the confirmation is judged: an ordinary account's tightening may be confirmed on the
	// last applied facts; an admin's account, or a re-enable, by a confirmer proven now (CP80, CP92)
	admin, err := administrator(ctx, tx, in.Account)
	if err != nil {
		return "", time.Time{}, err
	}
	until := time.Now().Add(effectpoint.ConfirmationValidity)
	basis, who, until, err := effectpoint.ConfirmerBasis(m, ctx, tx, confirmer, in, accountBinding(m, in.Account, in.TargetState, version, until), until,
		!admin && in.TargetState != "active")
	if err != nil {
		return "", time.Time{}, err
	}
	id := ids.New().String()
	_, err = tx.Exec(ctx, `INSERT INTO authz_confirmation (id, account, target_state, target_state_version, confirmer, basis,
		expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, in.Account, in.TargetState, version, who, basis, until)
	return id, until, err
}

// administrator: the account holds the authorization admin role (active or held: a suspended holding is still held).
func administrator(ctx context.Context, tx db.Tx, account string) (bool, error) {
	var is bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM authz_record WHERE state IN ('active', 'held')
		AND record_type = 'management_holding' AND body->>'system_role' = 'authorization_admin' AND body->>'holder' = $1)`,
		account).Scan(&is)
	return is, err
}

type accountConfirmation struct {
	confirmer, basis string
	usable           bool // unused and not expired
}

func accountConfirmationOf(ctx context.Context, tx db.Tx, id, account, state string, version int64) (*accountConfirmation, error) {
	if !core.UUIDText.MatchString(id) {
		return nil, nil
	}
	var c accountConfirmation
	err := tx.QueryRow(ctx, `SELECT confirmer, basis, consumed_by_change IS NULL AND expires_at > now()
		FROM authz_confirmation WHERE id = $1 AND account = $2 AND target_state = $3 AND target_state_version = $4`,
		id, account, state, version).Scan(&c.confirmer, &c.basis, &c.usable)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &c, err
}

// CheckAccountChange is AccountService.CheckAccountChange (contract-infra-authz alpha.3): it checks, it uses nothing.
func CheckAccountChange(m *core.Base, ctx context.Context, in *authzv3.CheckAccountChangeRequest) (*authzv3.CheckAccountChangeResponse, error) {
	if !core.UUIDText.MatchString(in.GetAccount()) || !accountStates[in.GetTargetState()] || !core.UUIDText.MatchString(in.GetRequester()) {
		return nil, errs.New(errs.ReasonRequestInvalid, "account, target_state and requester are required")
	}
	out := &authzv3.CheckAccountChangeResponse{}
	err := m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		if out.Administrator, err = administrator(ctx, tx, in.GetAccount()); err != nil {
			return err
		}
		verdict, reason, err := accountVerdict(m, ctx, tx, in, out.Administrator)
		out.Verdict, out.Reason = verdict, reason
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func accountVerdict(m *core.Base, ctx context.Context, tx db.Tx, in *authzv3.CheckAccountChangeRequest, admin bool) (
	authzv3.AccountChangeVerdict, string, error) {
	need := map[bool]string{true: "protected: the account holds the authorization admin role"}[admin]
	if need == "" && in.GetSecondPerson() {
		need = "second_person: the requester's basis is stale beyond T_tight"
	}
	if need == "" {
		return authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_ALLOWED, "", nil
	}
	if in.GetConfirmation() == "" {
		return authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_CONFIRMATION_REQUIRED, need, nil
	}
	refused := func(why string) (authzv3.AccountChangeVerdict, string, error) {
		return authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_REFUSED, why, nil
	}
	c, err := accountConfirmationOf(ctx, tx, in.GetConfirmation(), in.GetAccount(), in.GetTargetState(), in.GetSecurityVersion())
	switch {
	case err != nil:
		return 0, "", err
	case c == nil:
		return refused("the confirmation does not bind this account, status and version")
	case !c.usable:
		return refused("the confirmation is used or expired")
	case c.basis == effectpoint.BasisOwner:
		if in.GetTargetState() != "active" {
			return authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_ALLOWED, "", nil // a tightening: the owner stands in
		}
		switch others, err := effectpoint.OthersAvailable(m, ctx, tx, in.GetRequester(), in.GetAccount()); {
		case err != nil:
			return 0, "", err
		case others:
			return refused("another authorization admin is available: the owner does not stand in for a re-enable")
		}
		return authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_ALLOWED, "", nil
	}
	// row 22's exemption: for a tightening of an account that is no admin, the second person is judged by the last
	// applied facts (CP80); an admin's account needs a confirmer proven now, and one not provable decides nothing (CP92)
	lastApplied := !admin && in.GetTargetState() != "active"
	switch ok, err := effectpoint.Independent(m, ctx, tx, c.confirmer, !lastApplied, in.GetRequester(), in.GetAccount()); {
	case err != nil:
		return 0, "", err
	case ok == core.Disproven:
		return refused("the confirmer is the requester or the account itself (one person)")
	case ok == core.Unprovable:
		return authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_UNPROVABLE, "whether the confirmer is another person cannot be proven now", nil
	}
	switch ok, err := effectpoint.ConfirmerEligible(m, ctx, tx, c.confirmer, lastApplied); {
	case err != nil:
		return 0, "", err
	case ok == core.Unprovable:
		return authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_UNPROVABLE, "the confirmer's eligibility cannot be proven now", nil
	case ok != core.Proven:
		return refused("the confirmer is not a qualified authorization admin now")
	}
	return authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_ALLOWED, "", nil
}

// AccountChanged is the Changed hook's part for status transitions, in the transaction that applied the account's
// status (before the admins are judged again).
func AccountChanged(m *core.Base, ctx context.Context, tx db.Tx, principal string) error {
	state, _, data, ok, err := m.Accounts.Get(ctx, tx, principal)
	if err != nil || !ok || state != "complete" {
		return err
	}
	var rec struct {
		Status       string `json:"status"`
		Version      int64  `json:"security_version"`
		Confirmation string `json:"confirmation"`
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return err
	}
	var was string
	err = tx.QueryRow(ctx, "SELECT status FROM authz_account_seen WHERE principal = $1 FOR UPDATE", principal).Scan(&was)
	first := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !first {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO authz_account_seen (principal, status, version) VALUES ($1, $2, $3)
		ON CONFLICT (principal) DO UPDATE SET status = excluded.status, version = excluded.version`,
		principal, rec.Status, rec.Version); err != nil {
		return err
	}
	if first || was == rec.Status {
		return nil // first seen, or no transition
	}
	valid := false
	if rec.Confirmation != "" {
		c, err := accountConfirmationOf(ctx, tx, rec.Confirmation, principal, rec.Status, rec.Version-1)
		if err != nil {
			return err
		}
		if valid = c != nil && c.usable; valid { // by the facts last applied: not the account's own person
			ind, err := effectpoint.Independent(m, ctx, tx, c.confirmer, false, principal)
			if err != nil {
				return err
			}
			valid = ind != core.Disproven
		}
		if valid {
			if _, err := tx.Exec(ctx, "UPDATE authz_confirmation SET consumed_by_change = $2 WHERE id = $1", rec.Confirmation,
				"account:"+principal+"@"+strconv.FormatInt(rec.Version, 10)); err != nil {
				return err
			}
		}
	}
	admin, err := administrator(ctx, tx, principal)
	if err != nil || !admin {
		return err
	}
	ref := principal + "@" + strconv.FormatInt(rec.Version, 10)
	switch {
	case rec.Status == "active" && !valid: // re-enabled or unfrozen without a valid confirmation (CP42, CP47, CP40)
		m.RT.Logger.Error("an authorization admin's account was re-enabled without a valid confirmation: its holdings "+
			"await a reconfirmation (POST /api/authz/accounts/{principal}/reconfirm)", "event", "admin_account_pending_confirmation",
			"principal", principal, "status_revision", rec.Version)
		return setBackfill(ctx, tx, principal, true, ref)
	case rec.Status == "active":
		return setBackfill(ctx, tx, principal, false, ref)
	case !valid: // disabled or frozen without a confirmation: a source fact, it takes effect (security 08)
		m.RT.Logger.Error("an authorization admin's account was disabled or frozen without a confirmation (a console?)",
			"event", "admin_account_disabled_unconfirmed", "principal", principal, "status", rec.Status)
	}
	return nil
}

const backfillField = "confirmation_backfill_pending"

// setBackfill marks or clears 09a's confirmation_backfill_pending on the account's admin holdings (active or held);
// the security revision advances (an admin's availability changed).
func setBackfill(ctx context.Context, tx db.Tx, principal string, pending bool, ref string) error {
	body := `body || jsonb_build_object('` + backfillField + `', true, 'confirmation_backfill_ref', $2::text)`
	if !pending {
		body = `body - '` + backfillField + `' - 'confirmation_backfill_ref' || jsonb_build_object('backfill_cleared_by', $2::text)`
	}
	tag, err := tx.Exec(ctx, `UPDATE authz_record SET body = `+body+` WHERE state IN ('active', 'held')
		AND record_type = 'management_holding' AND body->>'system_role' = 'authorization_admin' AND body->>'holder' = $1
		AND coalesce((body->>'`+backfillField+`')::boolean, false) <> $3`, principal, ref, pending)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	return core.Advance(ctx, tx)
}

// pendingConfirmation: the account's admin holdings await a reconfirmation.
func pendingConfirmation(ctx context.Context, tx db.Tx, principal string) (bool, error) {
	var is bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM authz_record WHERE state IN ('active', 'held')
		AND record_type = 'management_holding' AND body->>'holder' = $1 AND (body->>'`+backfillField+`')::boolean)`,
		principal).Scan(&is)
	return is, err
}

// ReconfirmHTTP is the protected reconfirmation of an admin account pending confirmation: an available admin asks,
// with a confirmation of the account active at its current version by another admin (or the owner when none other
// is available); the holdings count again.
func ReconfirmHTTP(m *core.Base, c *httpx.Context) error {
	var in struct {
		Confirmation string `json:"confirmation"`
	}
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	s, _ := sdkauthz.From(c.Ctx())
	ctx, _, err := s.Check(c.Ctx(), core.OpChange, sdkauthz.Facts{})
	if err != nil {
		return err
	}
	u, _ := identity.UserFrom(ctx)
	account := c.Param("principal")
	awaiting := ""
	err = m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		awaiting = ""
		if _, err := tx.Exec(ctx, "SELECT 1 FROM authz_state FOR UPDATE"); err != nil { // the effect point's guard
			return err
		}
		switch pending, err := pendingConfirmation(ctx, tx, account); {
		case err != nil:
			return err
		case !pending:
			return errs.New(errs.ReasonNotFound, "no account awaits a reconfirmation")
		}
		switch ok, err := effectpoint.ConfirmerEligible(m, ctx, tx, u.Subject, false); { // the requester: an available admin now
		case err != nil:
			return err
		case ok != core.Proven:
			return errs.New(errs.ReasonPermissionDenied, "a reconfirmation is asked by an available authorization admin")
		}
		version, err := projectedVersion(m, ctx, tx, account)
		if err != nil {
			return err
		}
		verdict, why, err := accountVerdict(m, ctx, tx, &authzv3.CheckAccountChangeRequest{Account: account, TargetState: "active",
			SecurityVersion: version, Requester: u.Subject, Confirmation: in.Confirmation}, true)
		if err != nil {
			return err
		}
		switch verdict {
		case authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_CONFIRMATION_REQUIRED:
			awaiting = why // 09a: CONFIRMATION_REQUIRED, the confirmation first (security 08), nothing kept
			return nil
		case authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_REFUSED:
			return errs.New(errs.ReasonPermissionDenied, "the confirmation does not hold: "+why)
		}
		if _, err := tx.Exec(ctx, "UPDATE authz_confirmation SET consumed_by_change = $2 WHERE id = $1", in.Confirmation,
			"reconfirm:"+account); err != nil {
			return err
		}
		if err := setBackfill(ctx, tx, account, false, "reconfirm:"+in.Confirmation); err != nil {
			return err
		}
		if _, err := m.RT.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: core.OpChange,
			Outcome: audit.Succeeded, Actor: u.Subject, Target: map[string]any{"type": "account", "id": account},
			Changes: map[string]any{"reconfirmed": true, "confirmation": in.Confirmation}}); err != nil {
			return err
		}
		return effectpoint.JudgeAdmins(m, ctx, tx)
	})
	if err != nil {
		return err
	}
	if awaiting != "" {
		return c.JSON(202, map[string]any{"outcome": "awaiting_confirmation", "reason": "CONFIRMATION_REQUIRED", "detail": awaiting})
	}
	return c.NoContent(204)
}

// AccountPayloadHTTP answers what the deployment owner signs for an account's status change: the account, and the
// status at the account's current version (or the one asked), with its expiry from now.
func AccountPayloadHTTP(m *core.Base, c *httpx.Context, account string) error {
	state := c.Query("target_state")
	op := core.OpTighten
	if state == "active" {
		op = core.OpChange
	}
	s, _ := sdkauthz.From(c.Ctx())
	ctx, _, err := s.Check(c.Ctx(), op, sdkauthz.Facts{})
	if err != nil {
		return err
	}
	if !core.UUIDText.MatchString(account) || !accountStates[state] {
		return errs.New(errs.ReasonRequestInvalid, "account and target_state are required")
	}
	var version int64
	if v := c.Query("target_state_version"); v != "" {
		if version, err = strconv.ParseInt(v, 10, 64); err != nil {
			return errs.New(errs.ReasonRequestInvalid, "target_state_version is an integer")
		}
	} else if err := m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		version, err = projectedVersion(m, ctx, tx, account)
		return err
	}); err != nil {
		return err
	}
	o := accountBinding(m, account, state, version, time.Now().Add(effectpoint.ConfirmationValidity))
	return c.JSON(200, map[string]any{"deployment": o.Deployment, "target": o.Target, "expires_at": o.ExpiresAt,
		"expected_revision": o.ExpectedRevision})
}
