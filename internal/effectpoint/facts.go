package effectpoint

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
)

// CandidateOf is a candidate's common part (09a): its record type, validity and predecessor.
type CandidateOf struct {
	RecordType  string           `json:"record_type"`
	Valid       *sdkauthz.Window `json:"valid,omitempty"`
	Predecessor string           `json:"predecessor,omitempty"`
}

// Standing is the requester's management standing as the security records stand now: the active units, the units it
// holds, and whether one holding makes it an authorization admin.
type Standing struct {
	units  map[string]core.UnitBody
	held   []string
	admin  bool
	Limits *core.Limits `json:"-"` // the units' effective limits
}

// manages: the requester holds this unit or one above it.
func (s Standing) manages(unit string) bool {
	for u := unit; u != ""; u = s.units[u].Parent {
		if slices.ContainsFunc(s.held, func(h string) bool { return sameUnit(s.units, h, u) }) {
			return true
		}
		if _, ok := s.units[u]; !ok {
			return false
		}
	}
	return false
}

func invalid(detail string) *ChangeResult {
	return &ChangeResult{Outcome: "rejected", Reason: errs.ReasonRequestInvalid, Detail: detail}
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
func factsOf(m *core.Base, ctx context.Context, tx db.Tx, e Entry) (core.Facts, plan, *ChangeResult, error) {
	f := core.Facts{Trigger: e.Trigger, FromState: true, FromRevision: true, Contained: true, ConfirmersProvable: true,
		AdminsAfter: core.Proven}
	var p plan
	st, err := AdminState(ctx, tx)
	if err != nil {
		return f, p, nil, err
	}
	f.RecoveryPending = st != StateOperational // rows 13-14 (T6e)
	s, err := StandingOf(m, ctx, tx, e.Requester)
	if err != nil {
		return f, p, nil, err
	}
	var structural bool // the requester may make this change, as the security records stand
	var pre *ChangeResult
	switch {
	case e.job != nil:
		structural, pre, err = fired(m, ctx, tx, e, s, &f, &p)
	case e.Req.Release != nil:
		structural, pre, err = releasing(m, ctx, tx, e, s, &f, &p)
	case e.Req.Direction == core.Widen && e.Req.Target == "":
		structural, pre, err = submitted(m, ctx, tx, e, s, &f, &p)
	case e.Req.Target != "":
		structural, pre, err = onTarget(m, ctx, tx, e, s, &f, &p)
	case e.Req.Direction == core.Tighten && IsDisposition(e.Req.Candidate):
		structural, pre, err = disposing(m, ctx, tx, e, s, &f, &p)
	default:
		pre = invalid("a change is a widening with a candidate, or names its target")
	}
	if e.PlanItem && (!f.FromState || !f.FromRevision) { // the target moved since the preview: row 17 (security 08)
		f.FromState, f.FromRevision, f.RevisionsChanged = true, true, true
	}
	if err != nil || pre != nil || !f.FromState || !f.FromRevision || f.Kind == core.RestoreUncomputable {
		return f, p, pre, err // a restore of an uncomputable record does not check the original requester again
	}
	p.kind = f.Kind
	err = eligibility(m, ctx, tx, e.Requester, structural, &f)
	if f.Eligible == core.Unprovable {
		p.basis = f.Basis
	}
	return f, p, nil, err
}

// submitted reads a new widening from its candidate.
func submitted(m *core.Base, ctx context.Context, tx db.Tx, e Entry, s Standing, f *core.Facts, p *plan) (bool, *ChangeResult, error) {
	req := e.Req
	f.Kind = core.Widen
	var c CandidateOf
	if len(req.Candidate) == 0 || json.Unmarshal(req.Candidate, &c) != nil {
		return false, invalid("a widening carries its candidate record"), nil
	}
	if req.CandidateDigest != CandidateDigest(c.RecordType, req.Candidate) {
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
	structural, bad, pre, err := widening(m, ctx, tx, e.Requester, c.RecordType, req.Candidate, false, s, f, p)
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
		if u, ok := p.body.(core.UnitBody); ok && underItself(s.units, u.Parent, c.Predecessor) {
			return false, invalid("a management unit cannot be under the unit it supersedes"), nil
		}
		if err := supersedes(m, ctx, tx, c.Predecessor, false, f, p); err != nil {
			return false, nil, err
		}
	}
	if b, ok := p.body.(core.GrantBody); ok { // the budgets (security 07): row 19; the predecessor's segments give way
		if err := budgetOf(m, ctx, tx, b, f, p, c.Predecessor); err != nil {
			return false, nil, err
		}
	}
	return structural, nil, nil
}

// fired reads a saved widening whose job came due: the record as saved is checked again, now (security 08: every
// entry rechecks the requester and the containment). A record no longer scheduled, or moved on since the job was
// registered, voids the job (row 3).
func fired(m *core.Base, ctx context.Context, tx db.Tx, e Entry, s Standing, f *core.Facts, p *plan) (bool, *ChangeResult, error) {
	f.Kind = core.Widen
	t, err := LockTarget(ctx, tx, e.job.Record)
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
	if e.job.Trigger == TriggerRestore {
		return restoring(m, ctx, tx, t, s, f, p)
	}
	p.target, p.activate, p.recType = t, true, t.Type
	p.from, p.to, p.at, f.Future = t.ValidFrom, t.ValidUntil, t.EffectiveAt, t.Future
	structural, bad, pre, err := widening(m, ctx, tx, e.Requester, t.Type, t.Body, true, s, f, p)
	switch {
	case err != nil:
		return false, nil, err
	case pre != nil && pre.Retryable: // the owner's definitions are on their way: the job waits
		return false, &ChangeResult{Outcome: "processing", Reason: pre.Reason, Detail: pre.Detail}, nil
	case pre != nil || bad != "": // what it was checked against is gone: no longer contained (row 18)
		f.Contained = false
	}
	if t.Predecessor != "" {
		if err := supersedes(m, ctx, tx, t.Predecessor, true, f, p); err != nil {
			return false, nil, err
		}
	}
	if b, ok := p.body.(core.GrantBody); ok { // the budgets again, now (row 19): it does not count against itself
		if err := budgetOf(m, ctx, tx, b, f, p, t.ID, t.Predecessor); err != nil {
			return false, nil, err
		}
	}
	// a protected widening's confirmations, checked again now (security 08: confirmers re-checked at every entry)
	if p.confirmed, err = confirmationsOf(m, ctx, tx, nil, t, e.Requester, recordHolder(t), false, f); err != nil {
		return false, nil, err
	}
	// confirmed by the owner alone while another admin became unavailable within the cooling-off: it waits until
	// the cooling-off ends (once: a record already waiting it out is not held again)
	if e.job.Trigger == triggerConfirmed && f.OwnerOnly && t.CoolingOff == nil {
		recent, err := recentlyUnavailable(m, ctx, tx, e.Requester, recordHolder(t))
		if err != nil {
			return false, nil, err
		}
		if recent {
			until := time.Now().Add(CoolingOff)
			if p.at == nil || p.at.Before(until) {
				p.at = &until
			}
			f.Future, p.coolingOff = true, &until
		}
	}
	return structural, nil, nil
}

// restoring reads a held (uncomputable) record whose sources can be computed again (security 08,
// restore_uncomputable): its effective segments now decide (row 25 kept held when nothing is left, row 30 effective
// and to be reviewed when partly outside); the original requester's eligibility and confirmations are not checked
// again (D36: a grantor stepping down does not undo an effective grant).
func restoring(m *core.Base, ctx context.Context, tx db.Tx, t *Target, s Standing, f *core.Facts, p *plan) (bool, *ChangeResult, error) {
	f.Kind, p.target, p.restore, p.recType, f.Eligible = core.RestoreUncomputable, t, true, t.Type, core.Proven
	if t.HoldReason != "uncomputable" && t.HoldReason != "restore_pending" { // restore_pending: a release kept it (T6b)
		f.FromState = false
		return true, nil, nil
	}
	unit, segs, grantee := "", []sdkauthz.Segment(nil), ""
	switch t.Type {
	case "grant":
		var b core.GrantBody
		_ = json.Unmarshal(t.Body, &b)
		unit, segs, grantee = b.GovernanceUnit, b.Segments, b.Grantee
		if err := budgetOf(m, ctx, tx, b, f, p, t.ID); err != nil { // over a budget now: kept held (row 26)
			return false, nil, err
		}
	case "management_unit":
		var b core.UnitBody
		_ = json.Unmarshal(t.Body, &b)
		unit, segs, f.ManagementWiden = b.Parent, b.ManagedScope, true
	}
	lim := s.Limits.OfFor(unit, grantee)
	f.RestoredEmpty = lim == nil || !lim.Computable(segs) || !lim.All && len(lim.Cut(segs, grantee)) == 0
	f.PartlyOutside = !lim.Covers(segs, grantee)
	return true, nil, nil
}

// widening checks a widening's record-specific fields against the security records as they stand: whether the
// requester may make it (structural), and whether it is contained in its unit's limit. bad is why the candidate is
// not a valid one; pre a definition not there (see contains). stored: a saved record, its grant already expanded.
func widening(m *core.Base, ctx context.Context, tx db.Tx, requester, recType string, raw json.RawMessage, stored bool,
	s Standing, f *core.Facts, p *plan) (structural bool, bad string, pre *ChangeResult, err error) {
	var segs []sdkauthz.Segment
	var lim *core.Limit // the limit the segments must be within
	var grantee string  // a grant's: self is them (security 07); none for a unit's scope
	switch recType {
	case "management_unit":
		var b core.UnitBody
		_ = json.Unmarshal(raw, &b)
		if b.Root {
			return false, "only the install claim makes a root unit", nil, nil
		}
		if _, ok := s.units[b.Parent]; !ok {
			return false, "no active parent unit " + b.Parent, nil, nil
		}
		if why := unitShape(b); why != "" {
			return false, why, nil, nil
		}
		lim = s.Limits.Of(b.Parent)
		// re-delegation is its own action, within the parent's actions and depth (A131)
		structural, f.ManagementWiden, p.body, segs = s.managesWith(b.Parent, ActDelegate), true, b, b.ManagedScope
		if why := delegation(s.units, b, m.MaxDepth); why != "" {
			f.Contained, p.whyNot = false, why
		}
		f.NeedsConfirmation = true // a protected operation: a new or enlarged management unit (security 08)
		for _, op := range b.GrantableOperations {
			if lim == nil || !lim.All && !slices.Contains(lim.Ops, op) {
				f.Contained, p.whyNot = false, "operation "+op+" is not grantable in the parent unit"
			}
		}
	case "management_holding":
		var b core.HoldingBody
		_ = json.Unmarshal(raw, &b)
		if _, ok := s.units[b.Unit]; !ok {
			return false, "no active unit " + b.Unit, nil, nil
		}
		if b.SystemRole != "" && b.SystemRole != "authorization_admin" {
			return false, "system role " + b.SystemRole + " is not in this version", nil, nil
		}
		structural = s.managesWith(b.Unit, ActDelegate) && (b.SystemRole == "" || s.admin)
		f.ManagementWiden, p.body = true, b
		f.NeedsConfirmation = true // a protected operation: a management holding, a system role (security 08)
	case "role_revision":
		var b core.RoleBody
		_ = json.Unmarshal(raw, &b)
		structural, p.body = s.admin, b
	case "grant":
		var b core.GrantBody
		_ = json.Unmarshal(raw, &b)
		if _, ok := s.units[b.GovernanceUnit]; !ok {
			return false, "no active governance unit " + b.GovernanceUnit, nil, nil
		}
		if b.RoleRevision != "" && !stored {
			if b.Segments, err = RoleTemplate(ctx, tx, b.RoleRevision); err != nil {
				return false, err.Error(), nil, nil
			}
		}
		if b.Grantee == "" || len(b.Segments) == 0 {
			return false, "a grant needs a grantee and segments or a role revision", nil, nil
		}
		b.IssuedBy = requester
		action := ActGrant // a grant of segments; of a role revision, a binding (security 04)
		if b.RoleRevision != "" {
			action = ActBindRole
		}
		structural, p.body, segs, grantee = s.managesWith(b.GovernanceUnit, action), b, b.Segments, b.Grantee
		lim = s.Limits.OfFor(b.GovernanceUnit, grantee)
	default:
		return false, "record type " + recType + " is not in this version", nil, nil
	}
	if segs != nil {
		why, err := contains(m, ctx, tx, segs, lim, grantee)
		var rej *ChangeResult
		switch {
		case errors.As(err, &rej):
			return false, "", rej, nil
		case err != nil:
			return false, "", nil, err
		case why != "":
			f.Contained, p.whyNot = false, why
		}
	}
	return structural, "", nil, nil
}

// supersedes reads the record a renewal or widening supersedes: it must be active and of the same type, and the new
// grant must contain the old one (security 08). For a user that is the request's start state (row 4); for a saved
// record whose job came due, a predecessor ended since is a revision its validity depended on (row 17, A122).
func supersedes(m *core.Base, ctx context.Context, tx db.Tx, pred string, stored bool, f *core.Facts, p *plan) error {
	t, err := LockTarget(ctx, tx, pred)
	if err != nil {
		return err
	}
	// a predecessor a disposition holds may be renewed (CP31): the new record takes effect, evaluation keeps
	// suspending what meets the disposition, and the release ends the old one superseded (security 08)
	disposed := t != nil && t.State == "held" && t.HoldReason == "security_hold"
	switch {
	case t == nil || t.Type != p.recType || t.State != "active" && !disposed:
		if stored {
			f.RevisionsChanged = true
		} else {
			f.FromState = false
		}
	case p.recType == "grant":
		var old core.GrantBody
		_ = json.Unmarshal(t.Body, &old)
		nb := p.body.(core.GrantBody)
		f.Contained = f.Contained && coversAll(nb.Segments, old.Segments) && old.Grantee == nb.Grantee
	}
	p.successor, p.keepPredecessor = pred, disposed
	return nil
}

// onTarget reads a change of an existing record: a termination of one not yet effective, a revocation or
// relinquishment, or a narrowing.
func onTarget(m *core.Base, ctx context.Context, tx db.Tx, e Entry, s Standing, f *core.Facts, p *plan) (bool, *ChangeResult, error) {
	req, requester := e.Req, e.Requester
	t, err := LockTarget(ctx, tx, req.Target)
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
	case req.Direction == core.Tighten && req.Termination != "":
		f.Kind = core.Terminate
		if req.ExpectedStateRevision == nil {
			return false, invalid("a termination carries expected_state_revision"), nil
		}
		f.FromState = slices.Contains([]string{"requested", "awaiting_confirmation", "scheduled"}, t.State)
		switch req.Termination {
		case "withdraw":
			f.TerminatorEligible = requester == t.RequestedBy
			structural, p.endReason = f.TerminatorEligible, "withdrawn"
		case "cancel": // a manager's cancellation; or, in a cooling-off, any available admin's veto (row 7)
			veto, err := vetoes(m, ctx, tx, requester, t)
			if err != nil {
				return false, nil, err
			}
			f.TerminatorEligible = veto
			structural, p.endReason = veto || s.managesWith(unitOf, actionFor(t.Type)), "cancelled"
		case "reject": // a confirmer's rejection (row 7): someone who may confirm it now, not the applicant, not its object
			f.Rejection, f.FromState, p.endReason = true, f.FromState && t.State == "awaiting_confirmation", "rejected"
			ok, err := ConfirmerEligible(m, ctx, tx, requester, false)
			if err != nil {
				return false, nil, err
			}
			if requester == t.RequestedBy || requester == holderOf {
				ok = core.Disproven
			}
			// not provable now: the eligibility facts say so (row 9); disproven: refused (row 8)
			f.TerminatorEligible, structural = ok == core.Proven, ok != core.Disproven
		default:
			return false, invalid("termination is withdraw, reject or cancel"), nil
		}
	case req.Direction == core.Tighten:
		f.Kind = core.Tighten
		f.FromState = t.State == "active" || t.State == "held"
		relinquish := requester != "" && requester == holderOf
		manages := s.managesWith(unitOf, actionFor(t.Type)) // revoke for a grant, delegate_management otherwise (A131)
		structural = relinquish || manages || (t.Type == "role_revision" && s.admin)
		p.endReason = "revoked"
		if relinquish && !manages {
			p.endReason = "relinquished"
		}
		if e.selfOnly { // a relinquishment: one's own record only, whatever else one manages
			structural, p.endReason = relinquish, "relinquished"
		}
		// a record a disposition holds is not the disposed person's to give up (CP110, CP114): row 8
		if relinquish && t.HoldReason == "security_hold" {
			structural = false
		}
		if len(req.Candidate) > 0 { // a narrowing: a new content revision of the same record
			if req.CandidateDigest != CandidateDigest(t.Type, req.Candidate) {
				return false, invalid("candidate_digest is not the candidate's digest"), nil
			}
			narrowed, ok := narrows(t, req.Candidate)
			if !ok {
				return false, invalid("the candidate is not within the record: a change that widens is split into a tightening and a widening"), nil
			}
			p.body, p.endReason = narrowed, ""
		}
		if f.AffectsAdmins, err = AffectsAdmins(ctx, tx, s.units, t); err != nil {
			return false, nil, err
		}
		if f.AffectsAdmins && t.Type == "management_holding" {
			// a protected operation: tightening another authorization admin's holding (security 08, item 7)
			f.TightenNeedsConfirmation = holderOf != requester
		}
		if f.AffectsAdmins && p.endReason != "" { // it ends admin holdings: one admin must stay available (rows 27-28)
			ended, err := EndedAdminHoldings(ctx, tx, s.units, t)
			if err != nil {
				return false, nil, err
			}
			if f.AdminsAfter, err = AdminsAfter(m, ctx, tx, ended); err != nil {
				return false, nil, err
			}
		}
	case req.Direction == core.Neutral: // a display name: a new content revision, no access changes (security 08)
		f.Kind = core.Neutral
		f.FromState = t.State != "ended"
		if req.CandidateDigest != CandidateDigest(t.Type, req.Candidate) {
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
	// the confirmations, once the kind is known: a tightening that does not touch an admin's availability takes a
	// confirmer by the last applied facts (row 22's exemption)
	if p.confirmed, err = confirmationsOf(m, ctx, tx, req.ConfirmationIDs, t, requester, holderOf, !f.AffectsAdmins, f); err != nil {
		return false, nil, err
	}
	return structural, nil, nil
}

// contains proves the segments within the unit's limit; why is the first failure. Definitions not there come back as
// a *changeResult error: retryable when the owner's definitions are on their way, final when nobody owns the type.
func contains(m *core.Base, ctx context.Context, tx db.Tx, segs []sdkauthz.Segment, lim *core.Limit, grantee string) (string, error) {
	err := within(m, ctx, tx, segs, lim, grantee)
	var rej *errRejected
	switch {
	case err == nil:
		return "", nil
	case !errors.As(err, &rej):
		return "", err
	case rej.Reason == errs.ReasonContainmentNotProven:
		return rej.Detail, nil
	}
	return "", &ChangeResult{Outcome: "rejected", Reason: rej.Reason, Detail: rej.Detail,
		Retryable: rej.Reason == errs.ReasonDefinitionPending}
}

// StandingOf is a principal's management standing as the records stand now.
func StandingOf(m *core.Base, ctx context.Context, tx db.Tx, who string) (Standing, error) {
	units, err := Units(m, ctx, tx)
	if err != nil {
		return Standing{}, err
	}
	held, admin, err := HoldingsOf(ctx, tx, who)
	if err != nil {
		return Standing{}, err
	}
	return Standing{units: units, held: held, admin: admin, Limits: core.NewLimits(units)}, nil
}
