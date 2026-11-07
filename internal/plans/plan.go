package plans

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	core "github.com/brickKit/infra-authz/v3/internal/core"
	effectpoint "github.com/brickKit/infra-authz/v3/internal/effectpoint"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/jackc/pgx/v5"
)

// Batch plans (security 08, "批量计划"; security 04, "变更计划与批量生效"; 09a's change_plan; A132). A plan is drafted
// with its items (change requests without keys of their own), previewed (each item's target revisions recorded, the
// atom comparisons counted), confirmed against the preview, and executed by this member's job: one item at a time
// through the effect point, the initiator as requester, everything checked again (planrun.go). Every item ends with a
// state of its own; a plan never reports the batch as one success.

// Plan states and item states.
const (
	planDraft     = "draft"
	planPreviewed = "previewed"
	planConfirmed = "confirmed"
	planExecuting = "executing"
	planCompleted = "completed"
	PlanPartial   = "partially_completed"
	PlanCancelled = "cancelled"
	PlanExpired   = "expired"

	ItemPending     = "pending"
	ItemApplied     = "applied"
	ItemRejected    = "rejected"
	ItemNeedsReview = "needs_review"
)

// Plan limits: the items one plan holds, and the atom comparisons a preview may count (security 07's budget).
const (
	maxPlanItems            = 1000
	budgetPlanComparisons   = 100000
	DefaultPlanMaxAge       = 7 * 24 * time.Hour // AUTHZ_PLAN_MAX_AGE: from the preview to the end (security 08)
	DefaultPlanConfirmAbove = 100                // AUTHZ_PLAN_CONFIRM_ABOVE: items beyond which a second person confirms
)

type planItemIn struct {
	ItemKey string              `json:"item_key"`
	Request effectpoint.Request `json:"request"`
}

type planIn struct {
	PlanKey string       `json:"plan_key"`
	Items   []planItemIn `json:"items"`
}

// planRow is a plan as stored.
type planRow struct {
	ID, Initiator, PlanKey, State string
	PreviewDigest, Second         string
	PreviewedAt, ExpiresAt        *time.Time
	Comparisons                   int64
}

// planItem is one item as stored.
type planItem struct {
	Key     string
	Pos     int
	Request effectpoint.Request
	State   string
	Attempt int
	Record  string
	Result  json.RawMessage
	Reason  string
}

// digestOf is the canonical digest of a plan's content (09a's encoding): its items, keys and requests.
func digestOf(kind string, v any) (string, error) {
	body, _ := json.Marshal(v)
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var x any
	_ = d.Decode(&x)
	digest, err := canon.Digest(kind, 1, map[string]any{"content": x})
	if err != nil {
		return "", errs.New(errs.ReasonRequestInvalid, "the plan cannot be encoded: "+err.Error())
	}
	return digest, nil
}

// draft records a plan with its items, idempotent by the initiator's plan key.
func draft(m *core.Base, ctx context.Context, tx db.Tx, initiator string, in planIn) (string, error) {
	switch {
	case in.PlanKey == "":
		return "", errs.New(errs.ReasonRequestInvalid, "plan_key is required")
	case len(in.Items) == 0 || len(in.Items) > maxPlanItems:
		return "", errs.New(errs.ReasonRequestInvalid, fmt.Sprintf("a plan has 1 to %d items", maxPlanItems))
	}
	seen := map[string]bool{}
	for _, it := range in.Items {
		if seen[it.ItemKey] {
			return "", errs.New(errs.ReasonRequestInvalid, "every item has a key of its own: "+it.ItemKey)
		}
		if err := itemCheck(it); err != nil {
			return "", err
		}
		seen[it.ItemKey] = true
	}
	digest, err := digestOf("be.security.change_plan", in)
	if err != nil {
		return "", err
	}
	var id, was string
	err = tx.QueryRow(ctx, "SELECT id::text, draft_digest FROM authz_plan WHERE initiator = $1 AND plan_key = $2",
		initiator, in.PlanKey).Scan(&id, &was)
	switch {
	case err == nil && was == digest:
		return id, nil
	case err == nil:
		return "", errs.New(errs.ReasonChangeKeyConflict, "plan_key "+in.PlanKey+" names another plan")
	case !errors.Is(err, pgx.ErrNoRows):
		return "", err
	}
	id = ids.New().String()
	if _, err := tx.Exec(ctx, `INSERT INTO authz_plan (id, initiator, plan_key, draft_digest, plan_state)
		VALUES ($1, $2, $3, $4, 'draft')`, id, initiator, in.PlanKey, digest); err != nil {
		return "", err
	}
	for i, it := range in.Items {
		req, _ := json.Marshal(it.Request)
		if _, err := tx.Exec(ctx, `INSERT INTO authz_plan_item (plan, item_key, position, request, item_state)
			VALUES ($1, $2, $3, $4, 'pending')`, id, it.ItemKey, i, req); err != nil {
			return "", err
		}
	}
	return id, nil
}

// itemCheck: an item is a change request of its own, without a key (the plan derives it), and not a disposition.
func itemCheck(it planItemIn) error {
	r := it.Request
	switch {
	case it.ItemKey == "":
		return errs.New(errs.ReasonRequestInvalid, "every item has a key of its own")
	case r.ChangeKey != "":
		return errs.New(errs.ReasonRequestInvalid, "an item's key is its item_key: its request has no change_key")
	case r.Release != nil || effectpoint.IsDisposition(r.Candidate):
		return errs.New(errs.ReasonRequestInvalid, "dispositions and their releases are not planned")
	case r.Direction == core.Widen && (r.Target != "" || len(r.Candidate) == 0):
		return errs.New(errs.ReasonRequestInvalid, "item "+it.ItemKey+": a widening carries its candidate")
	case (r.Direction == core.Tighten || r.Direction == core.Neutral) && r.Target == "":
		return errs.New(errs.ReasonRequestInvalid, "item "+it.ItemKey+": a tightening or neutral change names its target")
	case r.Direction != core.Widen && r.Direction != core.Tighten && r.Direction != core.Neutral:
		return errs.New(errs.ReasonRequestInvalid, "item "+it.ItemKey+": direction is widen, tighten or neutral")
	}
	return nil
}

// lockPlan reads a plan for update; nil when there is none or it is not the caller's (an admin may read any).
func lockPlan(ctx context.Context, tx db.Tx, id string) (*planRow, error) {
	var p planRow
	var digest, second *string
	var comparisons *int64
	err := tx.QueryRow(ctx, `SELECT id::text, initiator, plan_key, plan_state, preview_digest, second_confirmer,
		previewed_at, expires_at, comparisons FROM authz_plan WHERE id::text = $1 FOR UPDATE`, id).
		Scan(&p.ID, &p.Initiator, &p.PlanKey, &p.State, &digest, &second, &p.PreviewedAt, &p.ExpiresAt, &comparisons)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if digest != nil {
		p.PreviewDigest = *digest
	}
	if second != nil {
		p.Second = *second
	}
	if comparisons != nil {
		p.Comparisons = *comparisons
	}
	return &p, err
}

func itemsOf(ctx context.Context, tx db.Tx, plan string) ([]planItem, error) {
	rows, err := tx.Query(ctx, `SELECT item_key, position, request, item_state, attempt, coalesce(record::text, ''),
		result, coalesce(reason, '') FROM authz_plan_item WHERE plan = $1 ORDER BY position`, plan)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []planItem
	for rows.Next() {
		var it planItem
		var req []byte
		if err := rows.Scan(&it.Key, &it.Pos, &req, &it.State, &it.Attempt, &it.Record, &it.Result, &it.Reason); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(req, &it.Request); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// previewItem records an item's target revisions as they stand (security 08: the preview records the candidate and
// the target revisions; the confirmation is for them) and counts its atom comparisons.
func previewItem(m *core.Base, ctx context.Context, tx db.Tx, s effectpoint.Standing, it *planItem) (int64, error) {
	r := &it.Request
	var t *effectpoint.Target
	if r.Target != "" {
		var err error
		if t, err = effectpoint.LockTarget(ctx, tx, r.Target); err != nil {
			return 0, err
		}
		if t == nil {
			return 0, errs.New(errs.ReasonRequestInvalid, "item "+it.Key+": no such record "+r.Target)
		}
		r.ExpectedStateRevision = &effectpoint.RevisionRef{Domain: effectpoint.StateDomain, Value: strconv.FormatInt(t.StateRevision, 10)}
		r.ExpectedRevision = &effectpoint.RevisionRef{Domain: effectpoint.ContentDomain, Value: strconv.FormatInt(t.Revision, 10)}
	}
	return comparisons(m, ctx, tx, s, *r, t)
}

// comparisons estimates an item's atom comparisons (security 07's budget for a plan): each candidate segment against
// each segment of what it must be within, dimension by dimension; at least one for any item.
func comparisons(m *core.Base, ctx context.Context, tx db.Tx, s effectpoint.Standing, r effectpoint.Request, t *effectpoint.Target) (int64, error) {
	count := func(segs, within []sdkauthz.Segment) int64 {
		var n int64
		for _, c := range segs {
			n += int64(len(within)) * int64(max1(len(c.Atoms)))
		}
		return max64(n, 1)
	}
	var c effectpoint.CandidateOf
	_ = json.Unmarshal(r.Candidate, &c)
	switch {
	case t != nil && len(r.Candidate) > 0: // a narrowing: the new segments against the current ones
		cur, next := segmentsOf(t.Type, t.Body), segmentsOf(t.Type, r.Candidate)
		return count(next, cur), nil
	case t != nil:
		return 1, nil
	case c.RecordType == "grant":
		var b core.GrantBody
		_ = json.Unmarshal(r.Candidate, &b)
		if b.RoleRevision != "" {
			segs, err := effectpoint.RoleTemplate(ctx, tx, b.RoleRevision)
			if err != nil {
				return 1, nil // checked when it runs
			}
			b.Segments = segs
		}
		lim := s.Limits.OfFor(b.GovernanceUnit, b.Grantee)
		if lim == nil || lim.All {
			return int64(max1(len(b.Segments))), nil
		}
		return count(b.Segments, lim.Segs), nil
	case c.RecordType == "management_unit":
		var b core.UnitBody
		_ = json.Unmarshal(r.Candidate, &b)
		lim := s.Limits.Of(b.Parent)
		if lim == nil || lim.All {
			return int64(max1(len(b.ManagedScope))), nil
		}
		return count(b.ManagedScope, lim.Segs), nil
	}
	return 1, nil
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// segmentsOf are a grant's or a unit's segments in a body.
func segmentsOf(recType string, body []byte) []sdkauthz.Segment {
	switch recType {
	case "grant":
		var b core.GrantBody
		_ = json.Unmarshal(body, &b)
		return b.Segments
	case "management_unit":
		var b core.UnitBody
		_ = json.Unmarshal(body, &b)
		return b.ManagedScope
	}
	return nil
}

// preview records every item's target revisions, counts the comparisons, and opens the plan's time to execute.
func preview(m *core.Base, ctx context.Context, tx db.Tx, p *planRow) error {
	if p.State != planDraft && p.State != planPreviewed {
		return errs.New(errs.ReasonChangeRevisionStale, "the plan is "+p.State+": only a draft is previewed")
	}
	s, err := effectpoint.StandingOf(m, ctx, tx, p.Initiator)
	if err != nil {
		return err
	}
	items, err := itemsOf(ctx, tx, p.ID)
	if err != nil {
		return err
	}
	var total int64
	for i := range items {
		n, err := previewItem(m, ctx, tx, s, &items[i])
		if err != nil {
			return err
		}
		total += n
	}
	if total > budgetPlanComparisons {
		return errs.New(errs.ReasonRequestInvalid, fmt.Sprintf(effectpoint.OverBudget+"%d atom comparisons (at most %d): split the plan",
			total, budgetPlanComparisons))
	}
	content := make([]planItemIn, len(items))
	for i, it := range items {
		req, _ := json.Marshal(it.Request)
		if _, err := tx.Exec(ctx, "UPDATE authz_plan_item SET request = $3 WHERE plan = $1 AND item_key = $2", p.ID, it.Key, req); err != nil {
			return err
		}
		content[i] = planItemIn{ItemKey: it.Key, Request: it.Request}
	}
	digest, err := digestOf("be.security.change_plan", map[string]any{"plan": p.ID, "items": content})
	if err != nil {
		return err
	}
	now := time.Now()
	until := now.Add(m.PlanMaxAge)
	if _, err := tx.Exec(ctx, `UPDATE authz_plan SET plan_state = 'previewed', preview_digest = $2, previewed_at = $3,
		expires_at = $4, comparisons = $5, updated_at = now() WHERE id = $1`, p.ID, digest, now, until, total); err != nil {
		return err
	}
	_, err = m.RT.Work.EnqueueAt(ctx, tx, JobPlanExpiry, planArgs{Plan: p.ID}, until)
	return err
}
