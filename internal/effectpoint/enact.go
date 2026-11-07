package effectpoint

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/ids"
)

// outVoid's answer: a job the record has moved on from; not a 09a outcome, only the job sees it.
const voided = "void"

// enact writes what the verdict calls for (security 08, "结果对记录状态的作用"). A saved widening (p.activate) is the
// record its job came due for: it takes effect, or ends rejected, in place.
func enact(m *core.Base, ctx context.Context, tx db.Tx, e Entry, p plan, v core.Verdict) (ChangeResult, error) {
	res := ChangeResult{Reason: v.Reason}
	change := e.Namespace + ":" + e.Key // the record's last_change
	switch v.Outcome {
	case core.OutVoid:
		res.Outcome = voided
		return res, nil
	case core.OutRejected:
		res.Outcome, res.Detail = "rejected", "row "+strconv.Itoa(v.Row)+p.whyFor(v.Row)
		switch {
		case p.restore: // a restore rejected: the record stays held (an operator's to look at)
			res.Record = p.target.ID
			m.RT.Logger.Warn("a held record's restore was rejected; it stays held", "record", p.target.ID, "reason", v.Reason)
			return res, nil
		case p.activate: // a job's widening of a saved record rejected, whatever the row: ended (rejected)
			res.Record = p.target.ID
			_, err := Transition(m, ctx, tx, p.target.ID, "ended", "rejected", "", change, v.Reason)
			return res, err
		case p.target == nil && p.kind == core.Widen && p.recType != "": // a new widening rejected for good: ended (rejected)
			id, err := insert(m, ctx, tx, e, p, "ended", "rejected", v.Reason)
			res.Record = id
			return res, err
		}
		return res, nil
	case core.OutRejectedRetryable:
		res.Outcome, res.Retryable, res.Detail = "rejected", true, "row "+strconv.Itoa(v.Row)
		return res, nil
	case core.OutProcessing:
		res.Outcome = "processing"
		return res, nil
	case core.OutAwaitingUnsaved:
		res.Outcome = "awaiting_confirmation"
		return res, nil
	case core.OutKeptHeld: // not bound: a later closure tries again; an excess is the operators' to see
		res.Outcome, res.Detail = "held_kept", strings.TrimPrefix(p.whyFor(v.Row), ": ")
		if res.Detail != "" {
			m.RT.Logger.Warn("a held record's restore is over a budget; it stays held", "record", p.target.ID, "detail", res.Detail)
		}
		return res, nil
	case core.OutScheduled:
		if p.activate && e.job.Trigger == triggerConfirmed { // confirmed, effective later: scheduled, its own job registered
			if p.coolingOff != nil { // its effective time first: a scheduled record has one
				if err := coolOff(m, ctx, tx, p.target, *p.coolingOff); err != nil {
					return res, err
				}
			}
			rev, err := Transition(m, ctx, tx, p.target.ID, "scheduled", "", "", change, "")
			if err != nil {
				return res, err
			}
			if _, err := m.RT.Work.EnqueueAt(ctx, tx, JobDue, firing{Record: p.target.ID, StateRevision: rev,
				Trigger: TriggerScheduled}, *p.at); err != nil {
				return res, err
			}
			res.Outcome, res.Record = "scheduled", p.target.ID
			res.NewRevision = &RevisionRef{Domain: StateDomain, Value: strconv.FormatInt(rev, 10)}
			return res, nil
		}
		if p.activate { // its job came early by the database's clock: it waits
			res.Outcome = "processing"
			return res, nil
		}
		return save(m, ctx, tx, e, p, "scheduled")
	case core.OutAwaitingSaved:
		if p.activate { // saved again, awaiting its confirmation (T5)
			rev, err := Transition(m, ctx, tx, p.target.ID, "awaiting_confirmation", "", "", change, "")
			res.Outcome, res.Record = "awaiting_confirmation", p.target.ID
			res.NewRevision = &RevisionRef{Domain: StateDomain, Value: strconv.FormatInt(rev, 10)}
			return res, err
		}
		return save(m, ctx, tx, e, p, "awaiting_confirmation")
	}
	p.review = v.Outcome == core.OutAppliedReview
	return apply(m, ctx, tx, e, p, change)
}

// save writes a widening that waits: awaiting its confirmation, or scheduled with the timed work item that brings
// it to the effect point when it is due (security 08, row 29).
func save(m *core.Base, ctx context.Context, tx db.Tx, e Entry, p plan, state string) (ChangeResult, error) {
	id, err := insert(m, ctx, tx, e, p, state, "", "")
	if err != nil {
		return ChangeResult{}, err
	}
	if state == "scheduled" {
		if _, err := m.RT.Work.EnqueueAt(ctx, tx, JobDue, firing{Record: id, StateRevision: 1, Trigger: TriggerScheduled},
			*p.at); err != nil {
			return ChangeResult{}, err
		}
	}
	return ChangeResult{Outcome: state, Record: id, NewRevision: &RevisionRef{Domain: StateDomain, Value: "1"}}, nil
}

// apply makes the change effective: a new record (superseding its predecessor), a saved one taking effect, a
// record ended, or a narrowing; the security revision advances.
func apply(m *core.Base, ctx context.Context, tx db.Tx, e Entry, p plan, change string) (ChangeResult, error) {
	if p.disp != nil {
		return dispose(m, ctx, tx, e, p, change)
	}
	if p.release != nil {
		return release(m, ctx, tx, e, p, change)
	}
	var res ChangeResult
	var id string
	var stateRev int64
	var err error
	switch {
	case p.activate:
		id = p.target.ID
		if stateRev, err = Transition(m, ctx, tx, id, "active", "", "", change, ""); err != nil {
			return res, err
		}
	case p.restore: // held (uncomputable) back to active; partly outside: to be reviewed (row 30)
		id = p.target.ID
		if stateRev, err = Transition(m, ctx, tx, id, "active", "", "", change, ""); err != nil {
			return res, err
		}
		if _, err := tx.Exec(ctx, "UPDATE authz_record SET review = $2 WHERE id = $1", id, p.review); err != nil {
			return res, err
		}
	case p.target == nil:
		if id, err = insert(m, ctx, tx, e, p, "active", "", ""); err != nil {
			return res, err
		}
		stateRev = 1
	case p.endReason != "":
		id = p.target.ID
		if stateRev, err = Transition(m, ctx, tx, id, "ended", p.endReason, "", change, ""); err != nil {
			return res, err
		}
	case p.kind == core.Neutral: // a new content revision; the state revision stays, no access changed (no new security revision)
		id = p.target.ID
		body, _ := json.Marshal(p.body)
		if err := tx.QueryRow(ctx, `UPDATE authz_record SET body = $2, revision = revision + 1, last_change = $3,
			updated_at = now() WHERE id = $1 RETURNING state_revision`, id, body, change).Scan(&stateRev); err != nil {
			return res, err
		}
		if err := audited(m, ctx, tx, e.operation(), e.Requester, core.Neutral, p.target.Type, id, "", p.basis); err != nil {
			return res, err
		}
		res.Outcome, res.Record = "applied", id
		res.NewRevision = &RevisionRef{Domain: StateDomain, Value: strconv.FormatInt(stateRev, 10)}
		return res, nil
	default: // a narrowing: a new content revision, the state kept
		id = p.target.ID
		body, _ := json.Marshal(p.body)
		if err := tx.QueryRow(ctx, `UPDATE authz_record SET body = $2, revision = revision + 1,
			state_revision = state_revision + 1, last_change = $3, updated_at = now() WHERE id = $1 RETURNING state_revision`,
			id, body, change).Scan(&stateRev); err != nil {
			return res, err
		}
	}
	if p.successor != "" && !p.keepPredecessor && (p.activate || p.target == nil) {
		if _, err := Transition(m, ctx, tx, p.successor, "ended", "superseded", "", change, ""); err != nil {
			return res, err
		}
		if p.recTypeOr() == "management_unit" { // what was under the old unit is under no active unit now
			if err := CloseAfter(m, ctx, tx, "management_unit", p.successor); err != nil {
				return res, err
			}
		}
	}
	// a held (uncomputable) record narrowed: its state revision moved, so a restore registered before is void (row 3);
	// its unit's closure looks at it again with the new content (CP115)
	if t := p.target; t != nil && p.kind == core.Tighten && p.endReason == "" && t.State == "held" && t.HoldReason == "uncomputable" {
		if err := CloseAfter(m, ctx, tx, "management_unit", recordUnit(t)); err != nil {
			return res, err
		}
	}
	// a source that tightened (ended or narrowed): the closure job keeps the books of what depends on it
	if t := p.target; t != nil && !p.activate && (t.Type == "management_unit" || t.Type == "role_revision") {
		if err := CloseAfter(m, ctx, tx, t.Type, t.ID); err != nil {
			return res, err
		}
	}
	if err := useConfirmations(ctx, tx, p.confirmed, change); err != nil {
		return res, err
	}
	rev, err := applied(m, ctx, tx, e.operation(), e.Requester, e.Req.Direction, p.recTypeOr(), id, p.basis)
	if err != nil {
		return res, err
	}
	if p.basis != nil {
		res.Basis = "last_applied"
	}
	res.Outcome, res.Record = "applied", id
	res.NewRevision = &RevisionRef{Domain: StateDomain, Value: strconv.FormatInt(stateRev, 10)}
	res.SecurityRevisions = []RevisionRef{{Domain: core.SecurityDomain, Value: strconv.FormatInt(rev, 10)}}
	return res, nil
}

func (p plan) recTypeOr() string {
	if p.target != nil {
		return p.target.Type
	}
	return p.recType
}

// insert writes a new record in state (with its end reason when it ends at once).
func insert(m *core.Base, ctx context.Context, tx db.Tx, e Entry, p plan, state, endReason, reason string) (string, error) {
	id := ids.New().String()
	if e.Replay != "" && p.target == nil { // a replayed widening keeps its record's identity: later records name it
		id = e.Replay
	}
	body, err := json.Marshal(p.body)
	if err != nil {
		return "", err
	}
	if !Allowed("", "", state, endReason, "") { // a new record starts only where the table says
		return "", refused(id, "", "", state, endReason, "")
	}
	var pred, end, why any
	if p.successor != "" {
		pred = p.successor
	}
	if endReason != "" {
		end, why = endReason, reason
	}
	if _, err = tx.Exec(ctx, `INSERT INTO authz_record (id, record_type, state, end_reason, body, requested_by, predecessor,
			effective_at, valid_from, valid_until, reason, last_change, candidate_digest)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`, id, p.recType, state, end, body, e.Requester, pred,
		p.at, p.from, p.to, why, e.Namespace+":"+e.Key, Nullable(e.Req.CandidateDigest)); err != nil {
		return "", err
	}
	if err := IndexSources(ctx, tx, id, p.recType, body); err != nil {
		return "", err
	}
	if state == "ended" {
		return id, nil
	}
	return id, expireAt(m, ctx, tx, id, p.to)
}

// Transition moves a record to state (with its end or hold reason, and a rejection's reason), advancing its state
// revision; it is the only writer of a record's state, and refuses a move the table (lifecycle.go) does not allow.
func Transition(m *core.Base, ctx context.Context, tx db.Tx, id, state, endReason, holdReason, change, reason string) (int64, error) {
	var fromState, fromHold string
	if err := tx.QueryRow(ctx, `SELECT state, coalesce(hold_reason, '') FROM authz_record WHERE id = $1 FOR UPDATE`, id).
		Scan(&fromState, &fromHold); err != nil {
		return 0, err
	}
	if !Allowed(fromState, fromHold, state, endReason, holdReason) {
		return 0, refused(id, fromState, fromHold, state, endReason, holdReason)
	}
	var rev int64
	err := tx.QueryRow(ctx, `UPDATE authz_record SET state = $2, end_reason = $3, hold_reason = $4,
		state_revision = state_revision + 1, last_change = coalesce($5, last_change), reason = coalesce($6, reason),
		updated_at = now() WHERE id = $1 RETURNING state_revision`, id, state, Nullable(endReason), Nullable(holdReason),
		Nullable(change), Nullable(reason)).Scan(&rev)
	if err != nil {
		return rev, err
	}
	return rev, m.RecordMoved(ctx, tx, id, state) // a plan item waiting on it (the plans module)
}

func Nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
