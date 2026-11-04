package authz

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
)

// candidateOf is a candidate's common part (09a): its record type, validity and predecessor.
type candidateOf struct {
	RecordType  string           `json:"record_type"`
	Valid       *sdkauthz.Window `json:"valid,omitempty"`
	Predecessor string           `json:"predecessor,omitempty"`
}

// standing is the requester's management standing as the security records stand now: the active units, the units it
// holds, and whether one holding makes it an authorization admin.
type standing struct {
	units  map[string]unitBody
	held   []string
	admin  bool
	limits *limits // the units' effective limits
}

// manages: the requester holds this unit or one above it.
func (s standing) manages(unit string) bool {
	for u := unit; u != ""; u = s.units[u].Parent {
		if slices.Contains(s.held, u) {
			return true
		}
		if _, ok := s.units[u]; !ok {
			return false
		}
	}
	return false
}

func invalid(detail string) *changeResult {
	return &changeResult{Outcome: "rejected", Reason: errs.ReasonRequestInvalid, Detail: detail}
}

// factsOf reads what the table decides on. pre is an answer before the table: an invalid request (final, it binds,
// D77) or a definition on its way (retryable for a user, processing for a job).
//
// What entered decides where the facts come from:
//   - a job (a saved record due): the record as saved, rechecked now (fired);
//   - a new widening: its candidate (submitted);
//   - a change of an existing record: the record and the request (onTarget).
//
// A change whose start state or state revision is stale is decided by rows 3-4 alone; otherwise the requester's
// eligibility is read last: the standing the branch proved, and the account as the identity source proves it.
func (m *Module) factsOf(ctx context.Context, tx db.Tx, e entry) (facts, plan, *changeResult, error) {
	f := facts{Trigger: e.trigger, FromState: true, FromRevision: true, Contained: true, ConfirmersProvable: true,
		AdminsAfter: proven}
	var p plan
	units, err := m.units(ctx, tx)
	if err != nil {
		return f, p, nil, err
	}
	held, admin, err := holdingsOf(ctx, tx, e.requester)
	if err != nil {
		return f, p, nil, err
	}
	s := standing{units: units, held: held, admin: admin, limits: newLimits(units)}
	var structural bool // the requester may make this change, as the security records stand
	var pre *changeResult
	switch {
	case e.job != nil:
		structural, pre, err = m.fired(ctx, tx, e, s, &f, &p)
	case e.req.Direction == Widen && e.req.Target == "":
		structural, pre, err = m.submitted(ctx, tx, e, s, &f, &p)
	case e.req.Target != "":
		structural, pre, err = m.onTarget(ctx, tx, e, s, &f, &p)
	default:
		pre = invalid("a change is a widening with a candidate, or names its target")
	}
	if err != nil || pre != nil || !f.FromState || !f.FromRevision {
		return f, p, pre, err
	}
	p.kind = f.Kind
	err = m.eligibility(ctx, tx, e.requester, structural, &f)
	return f, p, nil, err
}

// submitted reads a new widening from its candidate.
func (m *Module) submitted(ctx context.Context, tx db.Tx, e entry, s standing, f *facts, p *plan) (bool, *changeResult, error) {
	req := e.req
	f.Kind = Widen
	var c candidateOf
	if len(req.Candidate) == 0 || json.Unmarshal(req.Candidate, &c) != nil {
		return false, invalid("a widening carries its candidate record"), nil
	}
	if req.CandidateDigest != candidateDigest(c.RecordType, req.Candidate) {
		return false, invalid("candidate_digest is not the candidate's digest"), nil
	}
	p.recType = c.RecordType
	var err error
	if c.Valid != nil {
		if p.from, p.to, err = window(*c.Valid); err != nil {
			return false, invalid(err.Error()), nil
		}
	}
	if req.EffectiveFrom != "" {
		at, err := time.Parse(time.RFC3339Nano, req.EffectiveFrom)
		if err != nil {
			return false, invalid("effective_from is not an instant"), nil
		}
		if p.to != nil && !p.to.After(at) {
			return false, invalid("valid.until is after effective_from: the record would never give access"), nil
		}
		p.at, f.Future = &at, at.After(time.Now())
	}
	structural, bad, pre, err := m.widening(ctx, tx, e.requester, c.RecordType, req.Candidate, false, s, f, p)
	switch {
	case err != nil:
		return false, nil, err
	case pre != nil && pre.Retryable:
		return false, pre, nil
	case pre != nil: // nobody owns the type: final
		return false, invalid(pre.Detail), nil
	}
	if bad != "" {
		return false, invalid(bad), nil
	}
	if c.Predecessor != "" { // a renewal or a widening of an existing record: it supersedes it (security 08)
		if err := m.supersedes(ctx, tx, c.Predecessor, false, f, p); err != nil {
			return false, nil, err
		}
	}
	return structural, nil, nil
}

// fired reads a saved widening whose job came due: the record as saved is checked again, now (security 08: every
// entry rechecks the requester and the containment). A record no longer scheduled, or moved on since the job was
// registered, voids the job (row 3).
func (m *Module) fired(ctx context.Context, tx db.Tx, e entry, s standing, f *facts, p *plan) (bool, *changeResult, error) {
	f.Kind = Widen
	t, err := lockTarget(ctx, tx, e.job.Record)
	if err != nil {
		return false, nil, err
	}
	if t == nil {
		f.FromState = false
		return false, nil, nil
	}
	if f.FromState, f.FromRevision = t.State == e.job.from(), t.StateRevision == e.job.StateRevision; !f.FromState || !f.FromRevision {
		return false, nil, nil
	}
	p.target, p.activate, p.recType = t, true, t.Type
	p.from, p.to, p.at, f.Future = t.ValidFrom, t.ValidUntil, t.EffectiveAt, t.Future
	structural, bad, pre, err := m.widening(ctx, tx, e.requester, t.Type, t.Body, true, s, f, p)
	switch {
	case err != nil:
		return false, nil, err
	case pre != nil && pre.Retryable: // the owner's definitions are on their way: the job waits
		return false, &changeResult{Outcome: "processing", Reason: pre.Reason, Detail: pre.Detail}, nil
	case pre != nil || bad != "": // what it was checked against is gone: no longer contained (row 18)
		f.Contained = false
	}
	if t.Predecessor != "" {
		if err := m.supersedes(ctx, tx, t.Predecessor, true, f, p); err != nil {
			return false, nil, err
		}
	}
	return structural, nil, nil
}

// widening checks a widening's record-specific fields against the security records as they stand: whether the
// requester may make it (structural), and whether it is contained in its unit's limit. bad is why the candidate is
// not a valid one; pre a definition not there (see contains). stored: a saved record, its grant already expanded.
func (m *Module) widening(ctx context.Context, tx db.Tx, requester, recType string, raw json.RawMessage, stored bool,
	s standing, f *facts, p *plan) (structural bool, bad string, pre *changeResult, err error) {
	var segs []sdkauthz.Segment
	var lim *limit // the limit the segments must be within
	switch recType {
	case "management_unit":
		var b unitBody
		_ = json.Unmarshal(raw, &b)
		if b.Root {
			return false, "only the install claim makes a root unit", nil, nil
		}
		if _, ok := s.units[b.Parent]; !ok {
			return false, "no active parent unit " + b.Parent, nil, nil
		}
		lim = s.limits.of(b.Parent)
		structural, f.ManagementWiden, p.body, segs = s.manages(b.Parent), true, b, b.ManagedScope
		for _, op := range b.GrantableOperations {
			if lim == nil || !lim.all && !slices.Contains(lim.ops, op) {
				f.Contained = false
			}
		}
	case "management_holding":
		var b holdingBody
		_ = json.Unmarshal(raw, &b)
		if _, ok := s.units[b.Unit]; !ok {
			return false, "no active unit " + b.Unit, nil, nil
		}
		if b.SystemRole != "" && b.SystemRole != "authorization_admin" {
			return false, "system role " + b.SystemRole + " is not in this version", nil, nil
		}
		structural = s.manages(b.Unit) && (b.SystemRole == "" || s.admin)
		f.ManagementWiden, p.body = true, b
	case "role_revision":
		var b roleBody
		_ = json.Unmarshal(raw, &b)
		structural, p.body = s.admin, b
	case "grant":
		var b grantBody
		_ = json.Unmarshal(raw, &b)
		if _, ok := s.units[b.GovernanceUnit]; !ok {
			return false, "no active governance unit " + b.GovernanceUnit, nil, nil
		}
		if b.RoleRevision != "" && !stored {
			if b.Segments, err = roleTemplate(ctx, tx, b.RoleRevision); err != nil {
				return false, err.Error(), nil, nil
			}
		}
		if b.Grantee == "" || len(b.Segments) == 0 {
			return false, "a grant needs a grantee and segments or a role revision", nil, nil
		}
		b.IssuedBy = requester
		structural, p.body, lim, segs = s.manages(b.GovernanceUnit), b, s.limits.of(b.GovernanceUnit), b.Segments
	default:
		return false, "record type " + recType + " is not in this version", nil, nil
	}
	if segs != nil {
		why, err := m.contains(ctx, tx, segs, lim)
		var rej *changeResult
		switch {
		case errors.As(err, &rej):
			return false, "", rej, nil
		case err != nil:
			return false, "", nil, err
		case why != "":
			f.Contained = false
		}
	}
	return structural, "", nil, nil
}

// supersedes reads the record a renewal or widening supersedes: it must be active and of the same type, and the new
// grant must contain the old one (security 08). For a user that is the request's start state (row 4); for a saved
// record whose job came due, a predecessor ended since is a revision its validity depended on (row 17, A122).
func (m *Module) supersedes(ctx context.Context, tx db.Tx, pred string, stored bool, f *facts, p *plan) error {
	t, err := lockTarget(ctx, tx, pred)
	if err != nil {
		return err
	}
	switch {
	case t == nil || t.Type != p.recType || t.State != "active":
		if stored {
			f.RevisionsChanged = true
		} else {
			f.FromState = false
		}
	case p.recType == "grant":
		var old grantBody
		_ = json.Unmarshal(t.Body, &old)
		nb := p.body.(grantBody)
		f.Contained = f.Contained && coversAll(nb.Segments, old.Segments) && old.Grantee == nb.Grantee
	}
	p.successor = pred
	return nil
}

// onTarget reads a change of an existing record: a termination of one not yet effective, a revocation or
// relinquishment, or a narrowing.
func (m *Module) onTarget(ctx context.Context, tx db.Tx, e entry, s standing, f *facts, p *plan) (bool, *changeResult, error) {
	req, requester := e.req, e.requester
	t, err := lockTarget(ctx, tx, req.Target)
	if err != nil {
		return false, nil, err
	}
	if t == nil {
		return false, invalid("no such record " + req.Target), nil
	}
	p.target = t
	if req.ExpectedStateRevision != nil && req.ExpectedStateRevision.Value != strconv.FormatInt(t.StateRevision, 10) {
		f.FromRevision = false
	}
	if req.ExpectedRevision != nil && req.ExpectedRevision.Value != strconv.FormatInt(t.Revision, 10) {
		f.RevisionsChanged = true
	}
	unitOf, holderOf := recordUnit(t), recordHolder(t)
	structural := false
	switch {
	case req.Direction == Tighten && req.Termination != "":
		f.Kind = Terminate
		if req.ExpectedStateRevision == nil {
			return false, invalid("a termination carries expected_state_revision"), nil
		}
		f.FromState = slices.Contains([]string{"requested", "awaiting_confirmation", "scheduled"}, t.State)
		switch req.Termination {
		case "withdraw":
			f.TerminatorEligible = requester == t.RequestedBy
			structural, p.endReason = f.TerminatorEligible, "withdrawn"
		case "cancel":
			structural, p.endReason = s.manages(unitOf), "cancelled"
		case "reject": // a confirmer's rejection: confirmations come with T5; nobody qualifies yet
			f.Rejection, f.FromState, p.endReason = true, f.FromState && t.State == "awaiting_confirmation", "rejected"
		default:
			return false, invalid("termination is withdraw, reject or cancel"), nil
		}
	case req.Direction == Tighten:
		f.Kind = Tighten
		f.FromState = t.State == "active" || t.State == "held"
		relinquish := requester != "" && requester == holderOf
		structural = relinquish || s.manages(unitOf) || (t.Type == "role_revision" && s.admin)
		p.endReason = "revoked"
		if relinquish && !s.manages(unitOf) {
			p.endReason = "relinquished"
		}
		if len(req.Candidate) > 0 { // a narrowing: a new content revision of the same record
			if req.CandidateDigest != candidateDigest(t.Type, req.Candidate) {
				return false, invalid("candidate_digest is not the candidate's digest"), nil
			}
			narrowed, ok := narrows(t, req.Candidate)
			if !ok {
				return false, invalid("the candidate is not within the record: a change that widens is split into a tightening and a widening"), nil
			}
			p.body, p.endReason = narrowed, ""
		}
		if t.Type == "management_holding" {
			var h holdingBody
			_ = json.Unmarshal(t.Body, &h)
			if h.SystemRole == "authorization_admin" {
				f.AffectsAdmins = true
				if f.AdminsAfter, err = m.adminsBesides(ctx, tx, h.Holder); err != nil {
					return false, nil, err
				}
			}
		}
	case req.Direction == Neutral: // a display name: a new content revision, no access changes (security 08)
		f.Kind = Neutral
		f.FromState = t.State != "ended"
		if req.CandidateDigest != candidateDigest(t.Type, req.Candidate) {
			return false, invalid("candidate_digest is not the candidate's digest"), nil
		}
		renamed, ok := renames(t, req.Candidate)
		if !ok {
			return false, invalid("a neutral change changes only the name: a change of access is a tightening or a widening"), nil
		}
		// as for a tightening: the unit's managers; a role revision, or the root unit (no parent), an admin
		structural, p.body = s.manages(unitOf) || (t.Type == "role_revision" || unitOf == "") && s.admin, renamed
	default:
		return false, invalid("direction " + req.Direction + " is not in this version for an existing record"), nil
	}
	return structural, nil, nil
}

// contains proves the segments within the unit's limit; why is the first failure. Definitions not there come back as
// a *changeResult error: retryable when the owner's definitions are on their way, final when nobody owns the type.
func (m *Module) contains(ctx context.Context, tx db.Tx, segs []sdkauthz.Segment, lim *limit) (string, error) {
	err := m.within(ctx, tx, segs, lim, "")
	var rej *errRejected
	switch {
	case err == nil:
		return "", nil
	case !errors.As(err, &rej):
		return "", err
	case rej.Reason == errs.ReasonContainmentNotProven:
		return rej.Detail, nil
	}
	return "", &changeResult{Outcome: "rejected", Reason: rej.Reason, Detail: rej.Detail,
		Retryable: rej.Reason == errs.ReasonDefinitionPending}
}
