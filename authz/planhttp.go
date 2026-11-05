package authz

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/identity"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/jackc/pgx/v5"
)

// The routes of batch plans (A132): drafted, previewed, confirmed, cancelled and reviewed by their initiator under
// infra.authz.security_record.change (each item is checked at the effect point as its own kind); read by the
// initiator or an authorization admin under .read. A plan above AUTHZ_PLAN_CONFIRM_ABOVE items is a protected
// operation: confirmed with another authorization admin's confirmation (or the deployment owner's, with no other admin
// available), bound to the plan and its preview digest; an item reviewed again in such a plan, bound to the plan and
// <item>#<attempt>.

// planAs runs fn on the caller's own plan, admitted under op; a plan not the caller's is not found (an admin may read).
func (m *Module) planAs(c *httpx.Context, op string, read bool, fn func(context.Context, db.Tx, string, *planRow) error) error {
	s, _ := sdkauthz.From(c.Ctx())
	ctx, _, err := s.Check(c.Ctx(), op, sdkauthz.Facts{})
	if err != nil {
		return err
	}
	u, _ := identity.UserFrom(ctx)
	var out map[string]any
	err = m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		p, err := lockPlan(ctx, tx, c.Param("id"))
		if err != nil {
			return err
		}
		if p != nil && p.Initiator != u.Subject && read {
			if _, admin, err := holdingsOf(ctx, tx, u.Subject); err != nil || !admin {
				p = nil
			}
		}
		if p == nil || !read && p.Initiator != u.Subject {
			return errs.New(errs.ReasonNotFound, "no such plan")
		}
		if err := fn(ctx, tx, u.Subject, p); err != nil {
			return err
		}
		out, err = planOut(ctx, tx, p.ID)
		return err
	})
	if err != nil {
		var held *planHeld
		if errors.As(err, &held) {
			return c.JSON(202, map[string]any{"outcome": "awaiting_confirmation", "reason": "CONFIRMATION_REQUIRED",
				"detail": held.why})
		}
		return err
	}
	return c.JSON(200, out)
}

// planHeld: a confirmation the plan needs is missing; nothing changed.
type planHeld struct{ why string }

func (h *planHeld) Error() string { return h.why }

func (m *Module) createPlanHTTP(c *httpx.Context) error {
	var in planIn
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	s, _ := sdkauthz.From(c.Ctx())
	ctx, _, err := s.Check(c.Ctx(), OpChange, sdkauthz.Facts{})
	if err != nil {
		return err
	}
	u, _ := identity.UserFrom(ctx)
	var out map[string]any
	err = m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		id, err := m.draft(ctx, tx, u.Subject, in)
		if err != nil {
			return err
		}
		out, err = planOut(ctx, tx, id)
		return err
	})
	if err != nil {
		return err
	}
	return c.JSON(201, out)
}

func (m *Module) getPlanHTTP(c *httpx.Context) error {
	return m.planAs(c, OpRead, true, func(context.Context, db.Tx, string, *planRow) error { return nil })
}

func (m *Module) previewPlanHTTP(c *httpx.Context) error {
	return m.planAs(c, OpChange, false, func(ctx context.Context, tx db.Tx, _ string, p *planRow) error {
		return m.preview(ctx, tx, p)
	})
}

func (m *Module) confirmPlanHTTP(c *httpx.Context) error {
	var in struct {
		PreviewDigest   string   `json:"preview_digest"`
		ConfirmationIDs []string `json:"confirmation_ids,omitempty"`
	}
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	return m.planAs(c, OpChange, false, func(ctx context.Context, tx db.Tx, who string, p *planRow) error {
		switch {
		case p.State != planPreviewed:
			return errs.New(errs.ReasonChangeRevisionStale, "the plan is "+p.State+": a previewed plan is confirmed")
		case in.PreviewDigest != p.PreviewDigest:
			return errs.New(errs.ReasonChangeRevisionStale, "the plan is not as previewed (preview_digest)")
		case !time.Now().Before(*p.ExpiresAt):
			return errs.New(errs.ReasonChangeRevisionStale, "the plan has expired")
		}
		second, err := m.secondConfirmer(ctx, tx, p, p.PreviewDigest, in.ConfirmationIDs)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE authz_plan SET plan_state = 'confirmed', confirmed_at = now(),
			second_confirmer = $2, updated_at = now() WHERE id = $1`, p.ID, nullable(second)); err != nil {
			return err
		}
		_, err = m.rt.Work.Enqueue(ctx, tx, JobPlan, planArgs{Plan: p.ID})
		return err
	})
}

func (m *Module) cancelPlanHTTP(c *httpx.Context) error {
	return m.planAs(c, OpChange, false, func(ctx context.Context, tx db.Tx, _ string, p *planRow) error {
		switch p.State {
		case planCompleted, planPartial, planCancelled, planExpired:
			return errs.New(errs.ReasonChangeRevisionStale, "the plan has ended: "+p.State)
		}
		return m.endPlan(ctx, tx, p, planCancelled)
	})
}

// reviewItemHTTP confirms an item to be reviewed again (security 08: "合格的人重新确认新内容"): its request, new or as
// it was, previewed again, a new attempt pending. An item waiting on a record it saved is not run again: that record
// is confirmed itself.
func (m *Module) reviewItemHTTP(c *httpx.Context) error {
	var in struct {
		Request         *request `json:"request,omitempty"`
		ConfirmationIDs []string `json:"confirmation_ids,omitempty"`
	}
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	return m.planAs(c, OpChange, false, func(ctx context.Context, tx db.Tx, _ string, p *planRow) error {
		if p.State != planConfirmed && p.State != planExecuting {
			return errs.New(errs.ReasonChangeRevisionStale, "the plan is "+p.State+": items are reviewed while it executes")
		}
		var it planItem
		var req []byte
		err := tx.QueryRow(ctx, `SELECT item_key, request, item_state, attempt, coalesce(record::text, '')
			FROM authz_plan_item WHERE plan = $1 AND item_key = $2 FOR UPDATE`, p.ID, c.Param("item")).
			Scan(&it.Key, &req, &it.State, &it.Attempt, &it.Record)
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.New(errs.ReasonNotFound, "no such item")
		}
		if err != nil {
			return err
		}
		if it.State != itemNeedsReview || it.Record != "" {
			return errs.New(errs.ReasonChangeRevisionStale, "the item is "+it.State+": only one to be reviewed, with no saved record, runs again")
		}
		_ = json.Unmarshal(req, &it.Request)
		if in.Request != nil {
			if err := itemCheck(planItemIn{ItemKey: it.Key, Request: *in.Request}); err != nil {
				return err
			}
			it.Request = *in.Request
		}
		s, err := m.standingOf(ctx, tx, p.Initiator)
		if err != nil {
			return err
		}
		if _, err := m.previewItem(ctx, tx, s, &it); err != nil {
			return err
		}
		if _, err := m.secondConfirmer(ctx, tx, p, it.Key+"#"+strconv.Itoa(it.Attempt+1), in.ConfirmationIDs); err != nil {
			return err
		}
		out, _ := json.Marshal(it.Request)
		if _, err := tx.Exec(ctx, `UPDATE authz_plan_item SET request = $3, item_state = 'pending', attempt = attempt + 1,
			reason = NULL, updated_at = now() WHERE plan = $1 AND item_key = $2`, p.ID, it.Key, out); err != nil {
			return err
		}
		_, err = m.rt.Work.Enqueue(ctx, tx, JobPlan, planArgs{Plan: p.ID})
		return err
	})
}

// secondConfirmer: a plan above the threshold needs another person's confirmation bound to it and digest (a holding's
// confirmer proven now, or the owner's with no other admin available); it is used. "" for a plan within the threshold.
func (m *Module) secondConfirmer(ctx context.Context, tx db.Tx, p *planRow, digest string, list []string) (string, error) {
	var n int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM authz_plan_item WHERE plan = $1", p.ID).Scan(&n); err != nil {
		return "", err
	}
	if n <= m.planConfirmAbove {
		return "", nil
	}
	for _, id := range list {
		var confirmer, basis string
		var live bool
		err := tx.QueryRow(ctx, `SELECT confirmer, basis, consumed_by_change IS NULL AND expires_at > now()
			FROM authz_confirmation WHERE id::text = $1 AND plan::text = $2 AND plan_digest = $3 FOR UPDATE`, id, p.ID, digest).
			Scan(&confirmer, &basis, &live)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (!live || confirmer == p.Initiator) {
			continue
		}
		if err != nil {
			return "", err
		}
		if basis == basisOwner {
			others, err := m.othersAvailable(ctx, tx, p.Initiator, "")
			if err != nil || others {
				continue
			}
		} else if ok, err := m.confirmerEligible(ctx, tx, confirmer, false); err != nil || ok != proven {
			continue
		}
		_, err = tx.Exec(ctx, "UPDATE authz_confirmation SET consumed_by_change = $2 WHERE id::text = $1", id, "plan:"+p.ID)
		return confirmer, err
	}
	return "", &planHeld{why: "a plan of more than " + strconv.Itoa(m.planConfirmAbove) +
		" items is confirmed by another authorization admin, bound to the plan and " + digest}
}

// confirmPlan makes a confirmation of a plan (a second person's, above the threshold): bound to the plan and the
// digest it confirms (the preview digest, or <item>#<attempt> for an item reviewed again).
func (m *Module) confirmPlan(ctx context.Context, tx db.Tx, confirmer string, in confirmIn) (string, time.Time, error) {
	p, err := lockPlan(ctx, tx, in.Plan)
	if err != nil {
		return "", time.Time{}, err
	}
	if p == nil || p.PreviewDigest == "" || in.PlanDigest == "" {
		return "", time.Time{}, errs.New(errs.ReasonRequestInvalid, "a plan's confirmation names a previewed plan and the digest it confirms")
	}
	if confirmer == p.Initiator {
		return "", time.Time{}, errs.New(errs.ReasonPermissionDenied, "the initiator does not confirm their own plan")
	}
	until := *p.ExpiresAt
	o := sdkauthz.OwnerConfirmation{Deployment: m.deployment, Target: p.ID, ExpectedRevision: in.PlanDigest, ExpiresAt: canon.Time(until)}
	basis, who, until, err := m.confirmerBasis(ctx, tx, confirmer, in, o, until)
	if err != nil {
		return "", time.Time{}, err
	}
	id := ids.New().String()
	_, err = tx.Exec(ctx, `INSERT INTO authz_confirmation (id, plan, plan_digest, confirmer, basis, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, id, p.ID, in.PlanDigest, who, basis, until)
	return id, until, err
}

// planOut is a plan in 09a's change_plan shape, with its items.
func planOut(ctx context.Context, tx db.Tx, id string) (map[string]any, error) {
	p, err := lockPlan(ctx, tx, id)
	if err != nil || p == nil {
		return nil, err
	}
	items, err := itemsOf(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"id": p.ID, "plan_key": p.PlanKey, "initiator": p.Initiator, "plan_state": p.State}
	if p.PreviewedAt != nil {
		out["previewed_at"], out["expires_at"] = canon.Time(*p.PreviewedAt), canon.Time(*p.ExpiresAt)
		out["preview_digest"], out["comparisons"] = p.PreviewDigest, p.Comparisons
	}
	list := make([]map[string]any, len(items))
	for i, it := range items {
		x := map[string]any{"item_key": it.Key, "request": it.Request, "item_state": it.State, "attempt": it.Attempt}
		if it.Record != "" {
			x["record"] = it.Record
		}
		if len(it.Result) > 0 {
			x["result"] = it.Result
		}
		if it.Reason != "" {
			x["reason"] = it.Reason
		}
		list[i] = x
	}
	out["items"] = list
	return out, nil
}
