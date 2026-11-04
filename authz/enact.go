package authz

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/ids"
)

// outVoid's answer: a job the record has moved on from; not a 09a outcome, only the job sees it.
const voided = "void"

// enact writes what the verdict calls for (security 08, "结果对记录状态的作用"). A saved widening (p.activate) is the
// record its job came due for: it takes effect, or ends rejected, in place.
func (m *Module) enact(ctx context.Context, tx db.Tx, e entry, p plan, v verdict) (changeResult, error) {
	res := changeResult{Reason: v.Reason}
	change := e.namespace + ":" + e.key // the record's last_change
	switch v.Outcome {
	case outVoid:
		res.Outcome = voided
		return res, nil
	case outRejected:
		res.Outcome, res.Detail = "rejected", "row "+strconv.Itoa(v.Row)
		switch {
		case p.activate: // a job's widening of a saved record rejected, whatever the row: ended (rejected)
			res.Record = p.target.ID
			_, err := m.transition(ctx, tx, p.target.ID, "ended", "rejected", "", change, v.Reason)
			return res, err
		case p.target == nil && p.kind == Widen && p.recType != "": // a new widening rejected for good: ended (rejected)
			id, err := m.insert(ctx, tx, e, p, "ended", "rejected", v.Reason)
			res.Record = id
			return res, err
		}
		return res, nil
	case outRejectedRetryable:
		res.Outcome, res.Retryable, res.Detail = "rejected", true, "row "+strconv.Itoa(v.Row)
		return res, nil
	case outProcessing:
		res.Outcome = "processing"
		return res, nil
	case outAwaitingUnsaved:
		res.Outcome = "awaiting_confirmation"
		return res, nil
	case outKeptHeld:
		res.Outcome = "held_kept"
		return res, nil
	case outScheduled:
		if p.activate { // its job came early by the database's clock: it waits
			res.Outcome = "processing"
			return res, nil
		}
		return m.save(ctx, tx, e, p, "scheduled")
	case outAwaitingSaved:
		if p.activate { // saved again, awaiting its confirmation (T5)
			rev, err := m.transition(ctx, tx, p.target.ID, "awaiting_confirmation", "", "", change, "")
			res.Outcome, res.Record = "awaiting_confirmation", p.target.ID
			res.NewRevision = &revisionRef{Domain: stateDomain, Value: strconv.FormatInt(rev, 10)}
			return res, err
		}
		return m.save(ctx, tx, e, p, "awaiting_confirmation")
	}
	return m.apply(ctx, tx, e, p, change)
}

// save writes a widening that waits: awaiting its confirmation, or scheduled with the timed work item that brings
// it to the effect point when it is due (security 08, row 29).
func (m *Module) save(ctx context.Context, tx db.Tx, e entry, p plan, state string) (changeResult, error) {
	id, err := m.insert(ctx, tx, e, p, state, "", "")
	if err != nil {
		return changeResult{}, err
	}
	if state == "scheduled" {
		if _, err := m.rt.Work.EnqueueAt(ctx, tx, JobDue, firing{Record: id, StateRevision: 1, Trigger: triggerScheduled},
			*p.at); err != nil {
			return changeResult{}, err
		}
	}
	return changeResult{Outcome: state, Record: id, NewRevision: &revisionRef{Domain: stateDomain, Value: "1"}}, nil
}

// apply makes the change effective: a new record (superseding its predecessor), a saved one taking effect, a
// record ended, or a narrowing; the security revision advances.
func (m *Module) apply(ctx context.Context, tx db.Tx, e entry, p plan, change string) (changeResult, error) {
	var res changeResult
	var id string
	var stateRev int64
	var err error
	switch {
	case p.activate:
		id = p.target.ID
		if stateRev, err = m.transition(ctx, tx, id, "active", "", "", change, ""); err != nil {
			return res, err
		}
	case p.target == nil:
		if id, err = m.insert(ctx, tx, e, p, "active", "", ""); err != nil {
			return res, err
		}
		stateRev = 1
	case p.endReason != "":
		id = p.target.ID
		if stateRev, err = m.transition(ctx, tx, id, "ended", p.endReason, "", change, ""); err != nil {
			return res, err
		}
	default: // a narrowing: a new content revision, the state kept
		id = p.target.ID
		body, _ := json.Marshal(p.body)
		if err := tx.QueryRow(ctx, `UPDATE authz_record SET body = $2, revision = revision + 1,
			state_revision = state_revision + 1, last_change = $3, updated_at = now() WHERE id = $1 RETURNING state_revision`,
			id, body, change).Scan(&stateRev); err != nil {
			return res, err
		}
	}
	if p.successor != "" && (p.activate || p.target == nil) {
		if _, err := m.transition(ctx, tx, p.successor, "ended", "superseded", "", change, ""); err != nil {
			return res, err
		}
	}
	rev, err := m.applied(ctx, tx, e.requester, e.req.Direction, p.recTypeOr(), id)
	if err != nil {
		return res, err
	}
	res.Outcome, res.Record = "applied", id
	res.NewRevision = &revisionRef{Domain: stateDomain, Value: strconv.FormatInt(stateRev, 10)}
	res.SecurityRevisions = []revisionRef{{Domain: SecurityDomain, Value: strconv.FormatInt(rev, 10)}}
	return res, nil
}

func (p plan) recTypeOr() string {
	if p.target != nil {
		return p.target.Type
	}
	return p.recType
}

// insert writes a new record in state (with its end reason when it ends at once).
func (m *Module) insert(ctx context.Context, tx db.Tx, e entry, p plan, state, endReason, reason string) (string, error) {
	id := ids.New().String()
	body, err := json.Marshal(p.body)
	if err != nil {
		return "", err
	}
	var pred, end, why any
	if p.successor != "" {
		pred = p.successor
	}
	if endReason != "" {
		end, why = endReason, reason
	}
	_, err = tx.Exec(ctx, `INSERT INTO authz_record (id, record_type, state, end_reason, body, requested_by, predecessor,
			effective_at, valid_from, valid_until, reason, last_change)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`, id, p.recType, state, end, body, e.requester, pred,
		p.at, p.from, p.to, why, e.namespace+":"+e.key)
	return id, err
}

// transition moves a record to state (with its end or hold reason, and a rejection's reason), advancing its state
// revision.
func (m *Module) transition(ctx context.Context, tx db.Tx, id, state, endReason, holdReason, change, reason string) (int64, error) {
	var rev int64
	err := tx.QueryRow(ctx, `UPDATE authz_record SET state = $2, end_reason = $3, hold_reason = $4,
		state_revision = state_revision + 1, last_change = coalesce($5, last_change), reason = coalesce($6, reason),
		updated_at = now() WHERE id = $1 RETURNING state_revision`, id, state, nullable(endReason), nullable(holdReason),
		nullable(change), nullable(reason)).Scan(&rev)
	return rev, err
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
