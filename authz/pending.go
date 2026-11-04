package authz

import (
	"context"
	"encoding/json"

	"github.com/brickKit/be-sdk-go/v3/audit"
	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/jackc/pgx/v5"
)

// Pending recovery (security 08, "待恢复"; 09a's be.security.deployment_admin_state; T6e): after any change that may
// make an authorization admin holding unavailable — a source fact, a disposition, an end, a hold — the deployment's
// admins are judged again. Provably none available: recovery pending, each holding's cause recorded, a severe alert;
// not provable: only an alert. Recovery pending is left only through an administrator recovery; meanwhile widenings of
// the management structure are refused (rows 13-14), everything else goes on.

const (
	stateOperational     = "operational"
	stateRecoveryPending = "recovery_pending"
	stateAdminRecovery   = "admin_recovery"
)

// adminState is the deployment's authorization state.
func adminState(ctx context.Context, tx db.Tx) (string, error) {
	var s string
	err := tx.QueryRow(ctx, "SELECT admin_state FROM authz_state").Scan(&s)
	return s, err
}

// judgeAdmins judges the deployment's admins again (operational only: the other states are left by a recovery).
func (m *Module) judgeAdmins(ctx context.Context, tx db.Tx) error {
	st, err := adminState(ctx, tx)
	if err != nil || st == stateRecoveryPending {
		return err
	}
	if st == stateAdminRecovery { // operational again once the restored identity is provably available (T6f)
		return m.recoveredYet(ctx, tx)
	}
	var claimed bool // before the install claim there is no admin to lose
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM authz_record WHERE record_type = 'management_holding'
		AND body->>'system_role' = 'authorization_admin')`).Scan(&claimed); err != nil || !claimed {
		return err
	}
	switch avail, err := m.adminsAfter(ctx, tx, nil); {
	case err != nil:
		return err
	case avail == unprovable:
		m.rt.Logger.Warn("whether an authorization admin is available cannot be proven now")
		return nil
	case avail == proven:
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT id::text, state, coalesce(hold_reason, '') FROM authz_record
		WHERE record_type = 'management_holding' AND body->>'system_role' = 'authorization_admin' AND state <> 'ended'`)
	if err != nil {
		return err
	}
	type unavailable struct {
		Holding string `json:"holding"`
		Cause   string `json:"cause"`
	}
	causes, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (unavailable, error) {
		var u unavailable
		var state, hold string
		err := r.Scan(&u.Holding, &state, &hold)
		switch {
		case hold == "security_hold":
			u.Cause = "security_disposition"
		case hold == "uncomputable" || hold == "restore_pending":
			u.Cause = "uncomputable"
		default:
			u.Cause = "source_fact" // its account is not active
		}
		return u, err
	})
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(causes)
	if _, err := tx.Exec(ctx, `UPDATE authz_state SET admin_state = $1, admin_state_since = now(), unavailable_holdings = $2`,
		stateRecoveryPending, raw); err != nil {
		return err
	}
	m.rt.Logger.Error("no authorization admin is available: the deployment awaits an administrator recovery; "+
		"widenings of the management structure are refused until then", "unavailable_holdings", len(causes))
	_, err = m.rt.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: OpChange,
		Outcome: audit.Succeeded, Actor: ID, Target: map[string]any{"type": "deployment_admin_state"},
		Changes: map[string]any{"admin_state": stateRecoveryPending, "unavailable_holdings": causes}})
	return err
}

// adminStateHTTP answers the deployment's authorization state (09a's be.security.deployment_admin_state).
func (m *Module) adminStateHTTP(c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	ctx, _, err := s.Check(c.Ctx(), OpDispRead, sdkauthz.Facts{})
	if err != nil {
		return err
	}
	out := map[string]any{}
	err = m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var state, since string
		var from *string
		var unavailable json.RawMessage
		if err := tx.QueryRow(ctx, `SELECT admin_state, to_char(admin_state_since AT TIME ZONE 'UTC',
			'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), entered_from, unavailable_holdings FROM authz_state`).
			Scan(&state, &since, &from, &unavailable); err != nil {
			return err
		}
		out["state"], out["since"] = state, since
		if state == stateRecoveryPending {
			out["unavailable_holdings"] = unavailable
		}
		if from != nil {
			out["entered_from"] = *from
		}
		return nil
	})
	if err != nil {
		return err
	}
	return c.JSON(200, out)
}

// recoveredYet ends an administrator recovery when the identity it restored holds an active admin holding and the
// identity source proves its account active now; otherwise it stays in administrator recovery (CP74).
func (m *Module) recoveredYet(ctx context.Context, tx db.Tx) error {
	var identity *string
	if err := tx.QueryRow(ctx, "SELECT recovery_identity FROM authz_state").Scan(&identity); err != nil || identity == nil {
		return err
	}
	holdings, err := adminHoldingsOf(ctx, tx, *identity)
	if err != nil || len(holdings) == 0 {
		return err
	}
	a, err := m.accountOf(ctx, tx, *identity)
	if err != nil || a.now != proven {
		if err == nil {
			m.rt.Logger.Warn("administrator recovery: the restored identity is not available yet", "identity", *identity)
		}
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE authz_state SET admin_state = 'operational', admin_state_since = now(),
		entered_from = NULL, recovery_identity = NULL, unavailable_holdings = '[]'`); err != nil {
		return err
	}
	_, err = m.rt.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: OpChange,
		Outcome: audit.Succeeded, Actor: ID, Target: map[string]any{"type": "deployment_admin_state"},
		Changes: map[string]any{"admin_state": stateOperational, "restored": *identity}})
	return err
}
