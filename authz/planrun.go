package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/brickKit/be-sdk-go/v3/audit"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/evidence"
	"github.com/brickKit/be-sdk-go/v3/work"
	"github.com/jackc/pgx/v5"
)

// A plan's execution (security 08's item table): this member's job takes the next pending item, one per run, into
// the effect point under plan:<plan>:<item>:<attempt> with the initiator as requester, records its state, and
// enqueues the next run; an item that answers processing waits. Items whose target moved since the preview are
// judged by row 17 (needs review), not voided by row 3.

// Jobs of plans.
const (
	JobPlan       = "infra.authz.plan"
	JobPlanExpiry = "infra.authz.plan_expiry"
)

type planArgs struct {
	Plan string `json:"plan"`
}

// itemKey is an item run's derived key: a reviewed item runs again with new content under a new attempt.
func itemKey(plan, item string, attempt int) string {
	return "plan:" + plan + ":" + item + ":" + strconv.Itoa(attempt)
}

// itemState maps one run's result to the item's state (security 08's item table); wait: the run is retried later.
func itemState(res changeResult) (state string, wait bool) {
	switch {
	case res.Outcome == "applied" || res.Outcome == "scheduled":
		return itemApplied, false
	case res.Outcome == "awaiting_confirmation": // saved (row 20, followed by its record) or a confirmation missing
		return itemNeedsReview, false
	case res.Outcome == "processing" || res.Outcome == "rejected" && res.Retryable:
		return itemPending, true
	case res.Outcome == "rejected" && res.Reason == errs.ReasonChangeRevisionStale: // row 17
		return itemNeedsReview, false
	}
	return itemRejected, false
}

// runPlan is the job: the next pending item of a confirmed plan.
func (m *Module) runPlan(ctx context.Context, r *work.Run) error {
	var a planArgs
	if err := json.Unmarshal(r.Args, &a); err != nil || a.Plan == "" {
		return work.Permanent(fmt.Errorf("not a plan's job: %s", r.Args))
	}
	var denied *entry
	var res changeResult
	// a tightening item's intent before its transaction (assembly protocol 15, P12.16): the next pending item, read
	// without a lock; the transaction concludes it only if it runs that same item and it applies
	peeked, pending, err := m.planIntent(ctx, a.Plan)
	if err != nil {
		return err
	}
	concluded := false
	defer func() {
		if pending != nil && !concluded {
			if cerr := pending.Cancelled(ctx); cerr != nil {
				m.rt.Logger.Error("a plan item's cancelled conclusion could not be queued", "id", pending.ID, "error", cerr.Error())
			}
		}
	}()
	err = r.Complete(ctx, func(ctx context.Context, tx db.Tx) error {
		concluded = false
		p, err := lockPlan(ctx, tx, a.Plan)
		if err != nil || p == nil || p.State != planConfirmed && p.State != planExecuting {
			return err
		}
		if p.ExpiresAt != nil && !time.Now().Before(*p.ExpiresAt) {
			return m.endPlan(ctx, tx, p, planExpired)
		}
		var it planItem
		var req []byte
		err = tx.QueryRow(ctx, `SELECT item_key, request, attempt FROM authz_plan_item WHERE plan = $1 AND item_state = 'pending'
			ORDER BY position LIMIT 1 FOR UPDATE`, p.ID).Scan(&it.Key, &req, &it.Attempt)
		if errors.Is(err, pgx.ErrNoRows) {
			return m.settle(ctx, tx, p.ID)
		}
		if err != nil {
			return err
		}
		if err := json.Unmarshal(req, &it.Request); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE authz_plan SET plan_state = 'executing', updated_at = now() WHERE id = $1", p.ID); err != nil {
			return err
		}
		// a plan above the threshold stands on its second confirmer: one not qualified now leaves the item for review
		// (CP76)
		if p.Second != "" && p.Second != ownerName {
			switch ok, err := m.confirmerEligible(ctx, tx, p.Second, false); {
			case err != nil:
				return err
			case ok == unprovable:
				return errProcessing
			case ok == disproven:
				return m.setItem(ctx, tx, p.ID, it.Key, itemNeedsReview, "", nil, "confirmation_invalid", true)
			}
		}
		e := entry{namespace: ID, key: itemKey(p.ID, it.Key, it.Attempt), requester: p.Initiator, trigger: ByJob,
			req: it.Request, planItem: true}
		e.req.ChangeKey = e.key
		if e.digest, err = requestDigest(p.Initiator, e.req); err != nil {
			return err
		}
		var v verdict
		if res, v, err = m.effect(ctx, tx, e); err != nil {
			return err
		}
		if pending != nil && it.Key == peeked && res.Outcome == "applied" && v.Row != 1 {
			if err := pending.Effective(ctx, tx); err != nil {
				return err
			}
			concluded = true
		}
		state, wait := itemState(res)
		if wait {
			return errProcessing
		}
		out, _ := json.Marshal(res)
		denied = &e
		return m.setItem(ctx, tx, p.ID, it.Key, state, res.Record, out, "", true)
	})
	if errors.Is(err, errProcessing) {
		return work.Wait(fmt.Errorf("%w: %s %s", errProcessing, res.Reason, res.Detail))
	}
	if err == nil && denied != nil {
		m.denied(ctx, *denied, res)
	}
	return err
}

// planIntent writes the intent of a plan's next pending item when it is a tightening: the item's key and the pending
// evidence ("" and nil otherwise).
func (m *Module) planIntent(ctx context.Context, plan string) (string, *evidence.Pending, error) {
	if m.rt.Evidence == nil {
		return "", nil, nil
	}
	var key, initiator string
	var raw []byte
	err := m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT i.item_key, i.request, p.initiator FROM authz_plan_item i JOIN authz_plan p ON p.id = i.plan
			WHERE i.plan = $1 AND i.item_state = 'pending' ORDER BY i.position LIMIT 1`, plan).Scan(&key, &raw, &initiator)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	var req request
	if err := json.Unmarshal(raw, &req); err != nil || req.Direction != Tighten {
		return "", nil, nil
	}
	p, err := m.rt.Evidence.Intent(ctx, "security_tightening", "", evidence.Object{Type: Records, ID: req.Target,
		Version: revisionValue(req.ExpectedStateRevision)}, evidenceChange(initiator, req))
	return key, p, err
}

// setItem records an item's state; next enqueues the plan's next run.
func (m *Module) setItem(ctx context.Context, tx db.Tx, plan, item, state, record string, result []byte, reason string,
	next bool) error {
	if _, err := tx.Exec(ctx, `UPDATE authz_plan_item SET item_state = $3, record = coalesce($4::uuid, record),
		result = coalesce($5, result), reason = $6, updated_at = now() WHERE plan = $1 AND item_key = $2`,
		plan, item, state, nullable(record), result, nullable(reason)); err != nil {
		return err
	}
	if !next {
		return nil
	}
	_, err := m.rt.Work.Enqueue(ctx, tx, JobPlan, planArgs{Plan: plan})
	return err
}

// settle ends a plan whose items all have a final state: completed when every one applied, else partially completed.
// Items pending or to be reviewed keep it executing.
func (m *Module) settle(ctx context.Context, tx db.Tx, plan string) error {
	var open, rejected int
	if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE item_state IN ('pending', 'needs_review')),
		count(*) FILTER (WHERE item_state = 'rejected') FROM authz_plan_item WHERE plan = $1`, plan).Scan(&open, &rejected); err != nil {
		return err
	}
	if open > 0 {
		return nil
	}
	state := planCompleted
	if rejected > 0 {
		state = planPartial
	}
	_, err := tx.Exec(ctx, `UPDATE authz_plan SET plan_state = $2, updated_at = now() WHERE id = $1
		AND plan_state IN ('confirmed', 'executing')`, plan, state)
	return err
}

// followRecord moves the items waiting on a record a run saved (security 08: once saved, an item is not run again
// under its key): the record effective, the item applied; ended, rejected. Called on every record transition.
func (m *Module) followRecord(ctx context.Context, tx db.Tx, record, state string) error {
	next := map[string]string{"active": itemApplied, "scheduled": itemApplied, "ended": itemRejected}[state]
	if next == "" {
		return nil
	}
	rows, err := tx.Query(ctx, `UPDATE authz_plan_item SET item_state = $2, updated_at = now()
		WHERE record = $1 AND item_state = 'needs_review' RETURNING plan::text`, record, next)
	if err != nil {
		return err
	}
	plans, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, p := range plans {
		if err := m.settle(ctx, tx, p); err != nil {
			return err
		}
	}
	return nil
}

// endPlan cancels or expires a plan: pending items rejected (plan_terminated), items to be reviewed rejected
// (not_reviewed), and a record an item saved and not yet effective ends cancelled, under the guard (tighten × job, the
// plan's termination). Applied items stay as they are.
func (m *Module) endPlan(ctx context.Context, tx db.Tx, p *planRow, state string) error {
	if _, err := tx.Exec(ctx, "SELECT 1 FROM authz_state FOR UPDATE"); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT r.id::text FROM authz_plan_item i JOIN authz_record r ON r.id = i.record
		WHERE i.plan = $1 AND i.item_state = 'needs_review' AND r.state IN ('requested', 'awaiting_confirmation')`, p.ID)
	if err != nil {
		return err
	}
	saved, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	// the items first: the records' transitions then find no item waiting on them
	if _, err := tx.Exec(ctx, `UPDATE authz_plan_item SET reason = CASE item_state WHEN 'pending' THEN 'plan_terminated'
		ELSE 'not_reviewed' END, item_state = 'rejected', updated_at = now()
		WHERE plan = $1 AND item_state IN ('pending', 'needs_review')`, p.ID); err != nil {
		return err
	}
	change := ID + ":plan:" + p.ID + ":" + state
	for _, id := range saved {
		if _, err := m.transition(ctx, tx, id, "ended", "cancelled", "", change, "plan "+state); err != nil {
			return err
		}
	}
	if len(saved) > 0 {
		if err := advance(ctx, tx); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, "UPDATE authz_plan SET plan_state = $2, updated_at = now() WHERE id = $1", p.ID, state); err != nil {
		return err
	}
	_, err = m.rt.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: OpChange,
		Outcome: audit.Succeeded, Actor: ID, Target: map[string]any{"type": "change_plan", "id": p.ID},
		Changes: map[string]any{"plan_state": state, "records_cancelled": saved}})
	return err
}

// expirePlan is the plan's timed item at its expiry (security 08: from the preview, AUTHZ_PLAN_MAX_AGE).
func (m *Module) expirePlan(ctx context.Context, r *work.Run) error {
	var a planArgs
	if err := json.Unmarshal(r.Args, &a); err != nil || a.Plan == "" {
		return work.Permanent(fmt.Errorf("not a plan's expiry: %s", r.Args))
	}
	return r.Complete(ctx, func(ctx context.Context, tx db.Tx) error {
		p, err := lockPlan(ctx, tx, a.Plan)
		if err != nil || p == nil || p.ExpiresAt == nil || time.Now().Before(*p.ExpiresAt) {
			return err
		}
		switch p.State {
		case planPreviewed, planConfirmed, planExecuting:
			return m.endPlan(ctx, tx, p, planExpired)
		}
		return nil
	})
}

// reviewReplaced leaves for review the pending items of the plans a replaced admin initiated or confirmed (security
// 08's administrator recovery, tightening step 2; CP76).
func reviewReplaced(ctx context.Context, tx db.Tx, holder string) error {
	_, err := tx.Exec(ctx, `UPDATE authz_plan_item i SET item_state = 'needs_review', reason = 'confirmation_invalid',
		updated_at = now() FROM authz_plan p WHERE i.plan = p.id AND i.item_state = 'pending'
		AND p.plan_state IN ('confirmed', 'executing') AND (p.initiator = $1 OR p.second_confirmer = $1)`, holder)
	return err
}
