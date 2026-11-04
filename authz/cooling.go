package authz

import (
	"context"
	"time"

	"github.com/brickKit/be-sdk-go/v3/audit"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/jackc/pgx/v5"
)

// The cooling-off of a protected widening the deployment owner confirmed (security 08, "确认与受保护操作"; A127):
//   - the owner's key stands in for an independent confirmer of a widening only when no other authorization admin is
//     available; an admin the requester itself made unavailable within the cooling-off still counts as available
//     (the requester cannot clear the way for itself, CP108);
//   - when another admin's unavailability began within the cooling-off — whoever caused it, through this member or
//     the identity member, or for reasons this member cannot see — the widening waits as scheduled until the
//     cooling-off ends, counted from the confirmation that completed it (CP113);
//   - meanwhile any available authorization admin but its applicant may cancel it (a veto, row 7).

// CoolingOff is security 08's parameter: the cooling-off of a protected widening the deployment owner confirmed.
const CoolingOff = 24 * time.Hour

// admin is one authorization admin besides the excluded, as its holdings stand: one active holding makes it an admin
// now (its account decides whether it is available); otherwise its latest ended or held holding says when and by whom
// it stopped being one (a holding superseded by a renewal does not count).
type admin struct {
	holder      string
	active      bool
	recent      bool // not active: its last holding ended or was held within the cooling-off
	byRequester bool // not active: by one of the requester's own changes (its change key's namespace)
}

func adminsBesides(ctx context.Context, tx db.Tx, requester string, excluded ...string) ([]admin, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (body->>'holder') body->>'holder', state = 'active',
			updated_at > now() - $2::interval, coalesce(last_change LIKE $3 || ':%', false)
		FROM authz_record WHERE record_type = 'management_holding' AND body->>'system_role' = 'authorization_admin'
			AND body->>'holder' <> ALL($1) AND coalesce(end_reason, '') <> 'superseded'
		ORDER BY body->>'holder', state = 'active' DESC, updated_at DESC`, excluded, CoolingOff.String(), requester)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (admin, error) {
		var a admin
		err := r.Scan(&a.holder, &a.active, &a.recent, &a.byRequester)
		return a, err
	})
}

// madeUnavailableBy: an authorization admin besides the excluded that the requester's own change ended or held within
// the cooling-off, and that holds no active holding since. It still counts as available for the owner's key to stand
// in (CP108).
func madeUnavailableBy(ctx context.Context, tx db.Tx, requester string, excluded ...string) (bool, error) {
	as, err := adminsBesides(ctx, tx, requester, excluded...)
	if err != nil {
		return false, err
	}
	for _, a := range as {
		if !a.active && a.recent && a.byRequester {
			return true, nil
		}
	}
	return false, nil
}

// recentlyUnavailable: an authorization admin besides the requester and the object became unavailable within the
// cooling-off: its last holding ended or was held then, or it holds an active one with an account the identity source
// does not prove active now (when that began is not known here: counted).
func (m *Module) recentlyUnavailable(ctx context.Context, tx db.Tx, requester, object string) (bool, error) {
	as, err := adminsBesides(ctx, tx, requester, requester, object)
	if err != nil {
		return false, err
	}
	for _, a := range as {
		if !a.active && a.recent {
			return true, nil
		}
		if a.active {
			acct, err := m.accountOf(ctx, tx, a.holder)
			if err != nil || acct.now != proven {
				return err == nil, err
			}
		}
	}
	return false, nil
}

// vetoes: requester may cancel t as a veto (row 7): t waits out a cooling-off, and requester is an authorization admin
// proven available now who did not apply for it.
func (m *Module) vetoes(ctx context.Context, tx db.Tx, requester string, t *target) (bool, error) {
	if !t.InCoolingOff || t.State != "scheduled" || requester == t.RequestedBy {
		return false, nil
	}
	ok, err := m.confirmerEligible(ctx, tx, requester, false)
	return ok == proven, err
}

// coolOff writes a confirmed protected widening's cooling-off: effective when it ends, and the audit every authorization
// admin is told from (security 08: they and the registered contacts are notified; this version has no notification
// channel, so the audit and an error-level log carry it).
func (m *Module) coolOff(ctx context.Context, tx db.Tx, t *target, until time.Time) error {
	if _, err := tx.Exec(ctx, "UPDATE authz_record SET effective_at = $2, cooling_off_until = $2 WHERE id = $1",
		t.ID, until); err != nil {
		return err
	}
	m.rt.Logger.Error("a protected widening the deployment owner confirmed waits out the cooling-off: another authorization "+
		"admin became unavailable within it; any available admin but its applicant may cancel it",
		"record", t.ID, "type", t.Type, "applicant", t.RequestedBy, "until", until.UTC().Format(time.RFC3339))
	_, err := m.rt.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: OpChange,
		Outcome: audit.Succeeded, Actor: ID, Target: map[string]any{"type": t.Type, "id": t.ID},
		Changes: map[string]any{"action": "cooling_off", "applicant": t.RequestedBy, "until": canon.Time(until)}})
	return err
}
