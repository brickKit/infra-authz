package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/brickKit/be-sdk-go/v3/audit"
	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/brickKit/be-sdk-go/v3/projection"
	"github.com/jackc/pgx/v5"
)

// request is be.security.change_request (security 09a) as a user submits it: requested_by and trigger are not in it,
// the effect point takes them from the call (the token's subject; the user surface is the user trigger).
type request struct {
	ChangeKey             string          `json:"change_key"`
	Direction             string          `json:"direction"`             // widen, tighten, neutral
	Termination           string          `json:"termination,omitempty"` // withdraw, reject, cancel: ending a record not yet effective
	Target                string          `json:"target,omitempty"`
	ExpectedStateRevision *revisionRef    `json:"expected_state_revision,omitempty"`
	ExpectedRevision      *revisionRef    `json:"expected_revision,omitempty"`
	Candidate             json.RawMessage `json:"candidate,omitempty"`
	CandidateDigest       string          `json:"candidate_digest,omitempty"`
	EffectiveFrom         string          `json:"effective_from,omitempty"`
	ActingAs              string          `json:"acting_as,omitempty"`
	ConfirmationIDs       []string        `json:"confirmation_ids,omitempty"`
	Reason                string          `json:"reason,omitempty"`
}

// revisionRef is 09a's RevisionRef as this member numbers a record: its state revision and its content revision.
type revisionRef struct {
	Domain string `json:"domain"`
	Value  string `json:"value"`
}

const (
	stateDomain   = "authz.record.state"
	contentDomain = "authz.record.revision"
)

// changeResult is be.security.change_result; unbound answers a query by a key nothing bound.
type changeResult struct {
	ChangeKey         string        `json:"change_key"`
	Outcome           string        `json:"outcome"` // applied, rejected, processing, awaiting_confirmation, scheduled, held_kept, unbound
	Reason            string        `json:"reason,omitempty"`
	Detail            string        `json:"detail,omitempty"`
	Retryable         bool          `json:"-"` // a rejection that keeps the key free
	Record            string        `json:"record,omitempty"`
	NewRevision       *revisionRef  `json:"new_revision,omitempty"`
	SecurityRevisions []revisionRef `json:"security_revisions,omitempty"`
}

// candidateOf is a candidate's common part (09a): its record type, validity and predecessor.
type candidateOf struct {
	RecordType  string           `json:"record_type"`
	Valid       *sdkauthz.Window `json:"valid,omitempty"`
	Predecessor string           `json:"predecessor,omitempty"`
}

// target is the record a change is about, as the effect point reads it (locked).
type target struct {
	ID, Type, State, HoldReason, RequestedBy string
	StateRevision, Revision                  int64
	Body                                     json.RawMessage
}

// plan is what the effect point writes for each outcome of one change.
type plan struct {
	kind      string
	recType   string
	body      any // the new record's or the narrowed content
	target    *target
	endReason string // what an applied tightening ends the target with ("": a narrowing)
	from, to  *time.Time
	at        *time.Time // effective_from
	successor string     // the predecessor that a new record supersedes
}

var uuidText = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// change runs one user change at the effect point: one transaction under the deployment's guard, the facts read in
// it, the decision table, and the writes and the key binding its outcome calls for (security 08).
func (m *Module) change(ctx context.Context, requester string, req request) (changeResult, error) {
	if req.ChangeKey == "" {
		return changeResult{}, errs.New(errs.ReasonRequestInvalid, "change_key is required")
	}
	digest, err := requestDigest(requester, req)
	if err != nil {
		return changeResult{}, err
	}
	var res changeResult
	err = m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT 1 FROM authz_state FOR UPDATE"); err != nil { // the guard: one change at a time
			return err
		}
		f, p, pre, err := m.factsOf(ctx, tx, requester, req, digest)
		if err != nil {
			return err
		}
		if pre != nil { // answered before the table: the key's own rows, or a request the table never sees
			res = *pre
			return nil
		}
		v := decide(f)
		res, err = m.enact(ctx, tx, requester, req, p, v)
		if err != nil {
			return err
		}
		res.ChangeKey = req.ChangeKey
		if binds(v, p) {
			out, _ := json.Marshal(res)
			var rec any
			if res.Record != "" {
				rec = res.Record
			}
			_, err = tx.Exec(ctx, `INSERT INTO authz_change (requested_by, change_key, content_digest, result, record)
				VALUES ($1, $2, $3, $4, $5)`, requester, req.ChangeKey, digest, out, rec)
		}
		return err
	})
	if err != nil {
		return changeResult{}, err
	}
	if res.Outcome == "rejected" && !res.Retryable && res.Reason != errs.ReasonChangeKeyConflict {
		_ = m.rt.Audit.Denial(ctx, audit.Record{Category: audit.SecurityDenial, Operation: OpChange, Outcome: audit.Denied,
			Reason: res.Reason, Actor: requester, Changes: map[string]any{"direction": req.Direction, "target": req.Target}})
	}
	return res, nil
}

// requestDigest is the identity of a change's content under its key: the request in canonical form (09a).
func requestDigest(requester string, req request) (string, error) {
	body, _ := json.Marshal(req)
	var v map[string]any
	_ = json.Unmarshal(body, &v)
	v["requested_by"], v["trigger"] = requester, ByUser
	d, err := canon.Digest("be.security.change_request", 1, numbersAsText(v))
	if err != nil {
		return "", errs.New(errs.ReasonRequestInvalid, "the change cannot be encoded: "+err.Error())
	}
	return d, nil
}

// binds is the key table (security 08, "变更键"): applied, a final rejection and a saved record bind; processing, a
// retryable rejection and a tightening that waits for its confirmation do not. A conflict (row 2) leaves the key as
// its first change bound it.
func binds(v verdict, p plan) bool {
	if v.Row == 2 {
		return false
	}
	switch v.Outcome {
	case outApplied, outAppliedReview, outRejected, outScheduled, outAwaitingSaved:
		return true
	}
	return false
}

// factsOf reads what the table decides on. pre is an answer before the table (the key's rows 1 and 2 are the table's,
// but they need no other fact): a bound key, or an invalid request (a final rejection that binds, D77) or a
// definition on its way (retryable).
func (m *Module) factsOf(ctx context.Context, tx db.Tx, requester string, req request, digest string) (facts, plan,
	*changeResult, error) {
	f := facts{Trigger: ByUser, FromState: true, FromRevision: true, Contained: true, ConfirmersProvable: true,
		AdminsAfter: proven}
	var p plan
	var bound []byte
	var boundDigest string
	err := tx.QueryRow(ctx, "SELECT result, content_digest FROM authz_change WHERE requested_by = $1 AND change_key = $2",
		requester, req.ChangeKey).Scan(&bound, &boundDigest)
	switch {
	case err == nil && boundDigest == digest: // row 1: the bound result again, with the record's state now
		var res changeResult
		if err := json.Unmarshal(bound, &res); err != nil {
			return f, p, nil, err
		}
		return f, p, &res, nil
	case err == nil:
		f.Key = keyBoundElse
		return f, p, nil, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return f, p, nil, err
	}
	invalid := func(detail string) (facts, plan, *changeResult, error) {
		res := changeResult{ChangeKey: req.ChangeKey, Outcome: "rejected", Reason: errs.ReasonRequestInvalid, Detail: detail}
		out, _ := json.Marshal(res)
		_, err := tx.Exec(ctx, `INSERT INTO authz_change (requested_by, change_key, content_digest, result)
			VALUES ($1, $2, $3, $4)`, requester, req.ChangeKey, digest, out)
		return f, p, &res, err
	}
	units, err := m.units(ctx, tx)
	if err != nil {
		return f, p, nil, err
	}
	held, admin, err := holdingsOf(ctx, tx, requester)
	if err != nil {
		return f, p, nil, err
	}
	manages := func(unit string) bool { // the requester holds this unit or one above it
		for u := unit; u != ""; u = units[u].Parent {
			if slices.Contains(held, u) {
				return true
			}
			if _, ok := units[u]; !ok {
				return false
			}
		}
		return false
	}
	structural := false // the requester may make this change, as the security records stand
	switch {
	case req.Direction == Widen && req.Target == "":
		f.Kind = Widen
		var c candidateOf
		if len(req.Candidate) == 0 || json.Unmarshal(req.Candidate, &c) != nil {
			return invalid("a widening carries its candidate record")
		}
		if req.CandidateDigest != candidateDigest(c.RecordType, req.Candidate) {
			return invalid("candidate_digest is not the candidate's digest")
		}
		p.recType = c.RecordType
		if c.Valid != nil {
			if p.from, p.to, err = window(*c.Valid); err != nil {
				return invalid(err.Error())
			}
		}
		if req.EffectiveFrom != "" {
			at, err := time.Parse(time.RFC3339Nano, req.EffectiveFrom)
			if err != nil {
				return invalid("effective_from is not an instant")
			}
			p.at, f.Future = &at, at.After(time.Now())
			if f.Future { // the timed work item that makes it effective comes with T4d
				return f, p, &changeResult{ChangeKey: req.ChangeKey, Outcome: "rejected", Reason: errs.ReasonCapabilityUnsupported,
					Detail: "a widening effective in the future is not in this version"}, nil
			}
		}
		var segs []sdkauthz.Segment
		var unit unitBody
		var unitID string
		switch c.RecordType {
		case "management_unit":
			var b unitBody
			_ = json.Unmarshal(req.Candidate, &b)
			if b.Root {
				return invalid("only the install claim makes a root unit")
			}
			parent, ok := units[b.Parent]
			if !ok {
				return invalid("no active parent unit " + b.Parent)
			}
			structural, f.ManagementWiden, p.body, unit, unitID, segs = manages(b.Parent), true, b, parent, b.Parent, b.ManagedScope
			for _, op := range b.GrantableOperations {
				if !parent.Root && !slices.Contains(parent.GrantableOperations, op) {
					f.Contained = false
				}
			}
		case "management_holding":
			var b holdingBody
			_ = json.Unmarshal(req.Candidate, &b)
			if _, ok := units[b.Unit]; !ok {
				return invalid("no active unit " + b.Unit)
			}
			if b.SystemRole != "" && b.SystemRole != "authorization_admin" {
				return invalid("system role " + b.SystemRole + " is not in this version")
			}
			structural = manages(b.Unit) && (b.SystemRole == "" || admin)
			f.ManagementWiden, p.body = true, b
		case "role_revision":
			var b roleBody
			_ = json.Unmarshal(req.Candidate, &b)
			structural, p.body = admin, b
		case "grant":
			var b grantBody
			_ = json.Unmarshal(req.Candidate, &b)
			u, ok := units[b.GovernanceUnit]
			if !ok {
				return invalid("no active governance unit " + b.GovernanceUnit)
			}
			if b.RoleRevision != "" {
				if b.Segments, err = roleTemplate(ctx, tx, b.RoleRevision); err != nil {
					return invalid(err.Error())
				}
			}
			if b.Grantee == "" || len(b.Segments) == 0 {
				return invalid("a grant needs a grantee and segments or a role revision")
			}
			b.IssuedBy = requester
			structural, p.body, unit, unitID, segs = manages(b.GovernanceUnit), b, u, b.GovernanceUnit, b.Segments
		default:
			return invalid("record type " + c.RecordType + " is not in this version")
		}
		if segs != nil {
			switch why, err := m.contains(ctx, tx, segs, unit, unitID); {
			case err != nil:
				var rej *changeResult
				if errors.As(err, &rej) {
					if rej.Retryable {
						return f, p, rej, nil
					}
					return invalid(rej.Detail)
				}
				return f, p, nil, err
			case why != "":
				f.Contained = false
			}
		}
		if c.Predecessor != "" { // a renewal or a widening of an existing record: it supersedes it (security 08)
			t, err := lockTarget(ctx, tx, c.Predecessor)
			if err != nil {
				return f, p, nil, err
			}
			if t == nil || t.Type != c.RecordType || t.State != "active" {
				f.FromState = false
			} else if c.RecordType == "grant" {
				var old grantBody
				_ = json.Unmarshal(t.Body, &old)
				nb := p.body.(grantBody)
				f.Contained = f.Contained && coversAll(nb.Segments, old.Segments) && old.Grantee == nb.Grantee
			}
			p.successor = c.Predecessor
		}
	case req.Target != "":
		t, err := lockTarget(ctx, tx, req.Target)
		if err != nil {
			return f, p, nil, err
		}
		if t == nil {
			return invalid("no such record " + req.Target)
		}
		p.target = t
		if req.ExpectedStateRevision != nil && req.ExpectedStateRevision.Value != strconv.FormatInt(t.StateRevision, 10) {
			f.FromRevision = false
		}
		if req.ExpectedRevision != nil && req.ExpectedRevision.Value != strconv.FormatInt(t.Revision, 10) {
			f.RevisionsChanged = true
		}
		unitOf, holderOf := recordUnit(t), recordHolder(t)
		switch {
		case req.Direction == Tighten && req.Termination != "":
			f.Kind = Terminate
			if req.ExpectedStateRevision == nil {
				return invalid("a termination carries expected_state_revision")
			}
			f.FromState = slices.Contains([]string{"requested", "awaiting_confirmation", "scheduled"}, t.State)
			switch req.Termination {
			case "withdraw":
				f.TerminatorEligible = requester == t.RequestedBy
				structural, p.endReason = f.TerminatorEligible, "withdrawn"
			case "cancel":
				structural, p.endReason = manages(unitOf), "cancelled"
			case "reject": // a confirmer's rejection: confirmations come with T5; nobody qualifies yet
				f.Rejection, f.FromState, p.endReason = true, f.FromState && t.State == "awaiting_confirmation", "rejected"
			default:
				return invalid("termination is withdraw, reject or cancel")
			}
		case req.Direction == Tighten:
			f.Kind = Tighten
			f.FromState = t.State == "active" || t.State == "held"
			relinquish := requester != "" && requester == holderOf
			structural = relinquish || manages(unitOf) || (t.Type == "role_revision" && admin)
			p.endReason = "revoked"
			if relinquish && !manages(unitOf) {
				p.endReason = "relinquished"
			}
			if len(req.Candidate) > 0 { // a narrowing: a new content revision of the same record
				if req.CandidateDigest != candidateDigest(t.Type, req.Candidate) {
					return invalid("candidate_digest is not the candidate's digest")
				}
				narrowed, ok := narrows(t, req.Candidate)
				if !ok {
					return invalid("the candidate is not within the record: a change that widens is split into a tightening and a widening")
				}
				p.body, p.endReason = narrowed, ""
			}
			if t.Type == "management_holding" {
				var h holdingBody
				_ = json.Unmarshal(t.Body, &h)
				if h.SystemRole == "authorization_admin" {
					f.AffectsAdmins = true
					if f.AdminsAfter, err = m.adminsBesides(ctx, tx, h.Holder); err != nil {
						return f, p, nil, err
					}
				}
			}
		default:
			return invalid("direction " + req.Direction + " is not in this version for an existing record")
		}
	default:
		return invalid("a change is a widening with a candidate, or names its target")
	}
	p.kind = f.Kind
	// the requester as the identity source proves it now (a change is a high-risk operation) and by the last facts
	acct, last, quarantined, err := m.accountOf(ctx, tx, requester)
	if err != nil {
		return f, p, nil, err
	}
	switch {
	case !structural || acct == disproven:
		f.Eligible = disproven
	case acct == proven:
		f.Eligible = proven
	default:
		f.Eligible, f.LastApplied, f.Quarantined = unprovable, last, quarantined
	}
	return f, p, nil, nil
}

// accountOf proves the requester's account active: at D_src_high, and by the last applied facts (any age).
func (m *Module) accountOf(ctx context.Context, tx db.Tx, principal string) (now proof, last, quarantined bool, err error) {
	asked := map[string][]string{principal: {principal}}
	j, err := m.accounts.JudgeMany(ctx, tx, asked, m.srcHigh)
	if err != nil {
		return unprovable, false, false, err
	}
	active := func(jd projection.Judged) (proof, error) {
		switch jd.Verdict {
		case projection.Usable:
			var rec struct {
				Status string `json:"status"`
			}
			if err := json.Unmarshal(jd.Data, &rec); err != nil {
				return unprovable, err
			}
			if rec.Status == "active" {
				return proven, nil
			}
			return disproven, nil
		case projection.ProvablyAbsent: // no account: nobody to be eligible
			return disproven, nil
		}
		return unprovable, nil
	}
	if now, err = active(j.Records[principal]); err != nil || now != unprovable {
		return now, now == proven, false, err
	}
	quarantined = j.Source == projection.Usable // the source is fresh, this account is not provable: quarantined
	lj, err := m.accounts.JudgeMany(ctx, tx, asked, 100*365*24*time.Hour)
	if err != nil {
		return unprovable, false, false, err
	}
	l, err := active(lj.Records[principal])
	return unprovable, l == proven, quarantined, err
}

// adminsBesides proves whether an authorization admin other than holder stays available (security 08, rows 27-28).
func (m *Module) adminsBesides(ctx context.Context, tx db.Tx, holder string) (proof, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT body->>'holder' FROM authz_record WHERE state = 'active'
		AND record_type = 'management_holding' AND body->>'system_role' = 'authorization_admin' AND body->>'holder' <> $1`, holder)
	if err != nil {
		return unprovable, err
	}
	others, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(others) == 0 {
		return disproven, err
	}
	result := disproven
	for _, o := range others {
		a, _, _, err := m.accountOf(ctx, tx, o)
		if err != nil {
			return unprovable, err
		}
		switch a {
		case proven:
			return proven, nil
		case unprovable:
			result = unprovable
		}
	}
	return result, nil
}

// contains proves the segments within the unit's limit; why is the first failure. Definitions not there come back as
// a *changeResult error: retryable when the owner's definitions are on their way, final when nobody owns the type.
func (m *Module) contains(ctx context.Context, tx db.Tx, segs []sdkauthz.Segment, unit unitBody, unitID string) (string, error) {
	err := m.within(ctx, tx, segs, unit, "")
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

func (r *changeResult) Error() string { return r.Reason + ": " + r.Detail }

// candidateDigest is the digest a candidate carries: its canonical form under its record type (09a).
func candidateDigest(recordType string, raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	d, err := canon.Digest("be.security."+recordType, 1, numbersAsText(v))
	if err != nil {
		return ""
	}
	return d
}

func window(w sdkauthz.Window) (*time.Time, *time.Time, error) {
	var from, to *time.Time
	if w.From != "" {
		t, err := time.Parse(time.RFC3339Nano, w.From)
		if err != nil {
			return nil, nil, fmt.Errorf("valid.from is not an instant")
		}
		from = &t
	}
	if w.Until != "" {
		t, err := time.Parse(time.RFC3339Nano, w.Until)
		if err != nil {
			return nil, nil, fmt.Errorf("valid.until is not an instant")
		}
		to = &t
	}
	if from != nil && to != nil && !to.After(*from) {
		return nil, nil, fmt.Errorf("valid.until is after valid.from")
	}
	return from, to, nil
}

func lockTarget(ctx context.Context, tx db.Tx, id string) (*target, error) {
	if !uuidText.MatchString(id) {
		return nil, nil
	}
	var t target
	var hold *string
	err := tx.QueryRow(ctx, `SELECT id::text, record_type, state, hold_reason, requested_by, state_revision, revision, body
		FROM authz_record WHERE id = $1 FOR UPDATE`, id).Scan(&t.ID, &t.Type, &t.State, &hold, &t.RequestedBy,
		&t.StateRevision, &t.Revision, &t.Body)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if hold != nil {
		t.HoldReason = *hold
	}
	return &t, err
}

// recordUnit is the unit that governs a record (who may tighten it); recordHolder whose it is (who may relinquish it).
func recordUnit(t *target) string {
	var b struct {
		GovernanceUnit string `json:"governance_unit"`
		Unit           string `json:"unit"`
		Parent         string `json:"parent"`
	}
	_ = json.Unmarshal(t.Body, &b)
	switch t.Type {
	case "grant":
		return b.GovernanceUnit
	case "management_holding":
		return b.Unit
	case "management_unit":
		return b.Parent
	}
	return ""
}

func recordHolder(t *target) string {
	var b struct {
		Grantee string `json:"grantee"`
		Holder  string `json:"holder"`
	}
	_ = json.Unmarshal(t.Body, &b)
	if t.Type == "grant" {
		return b.Grantee
	}
	if t.Type == "management_holding" {
		return b.Holder
	}
	return ""
}

// coversAll: every old segment is contained in one of the new ones (a superseding record contains the old, security 08).
func coversAll(next, old []sdkauthz.Segment) bool {
	for _, o := range old {
		if !slices.ContainsFunc(next, func(n sdkauthz.Segment) bool { return contained(o, n, "") == nil }) {
			return false
		}
	}
	return true
}

// narrows reads a narrowing's candidate: the same record with fewer segments, each within the current ones; nothing
// else may change.
func narrows(t *target, raw json.RawMessage) (any, bool) {
	switch t.Type {
	case "grant":
		var cur, next grantBody
		_ = json.Unmarshal(t.Body, &cur)
		if json.Unmarshal(raw, &next) != nil || next.Grantee != cur.Grantee || next.GovernanceUnit != cur.GovernanceUnit ||
			len(next.Segments) == 0 || !coversAll(cur.Segments, next.Segments) {
			return nil, false
		}
		next.IssuedBy, next.RoleRevision = cur.IssuedBy, cur.RoleRevision
		return next, true
	case "management_unit":
		var cur, next unitBody
		_ = json.Unmarshal(t.Body, &cur)
		if json.Unmarshal(raw, &next) != nil || next.Parent != cur.Parent || cur.Root || !coversAll(cur.ManagedScope, next.ManagedScope) {
			return nil, false
		}
		for _, op := range next.GrantableOperations {
			if !slices.Contains(cur.GrantableOperations, op) {
				return nil, false
			}
		}
		return next, true
	}
	return nil, false
}

// enact writes what the verdict calls for (security 08, "结果对记录状态的作用").
func (m *Module) enact(ctx context.Context, tx db.Tx, requester string, req request, p plan, v verdict) (changeResult, error) {
	res := changeResult{Reason: v.Reason}
	switch v.Outcome {
	case outRejected:
		res.Outcome, res.Detail = "rejected", "row "+strconv.Itoa(v.Row)
		if p.target == nil && p.kind == Widen && p.recType != "" { // a new widening rejected for good: ended (rejected)
			id, err := m.insert(ctx, tx, requester, req, p, "ended", "rejected", v.Reason)
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
	case outAwaitingSaved, outScheduled:
		state := map[string]string{outAwaitingSaved: "awaiting_confirmation", outScheduled: "scheduled"}[v.Outcome]
		id, err := m.insert(ctx, tx, requester, req, p, state, "", "")
		res.Outcome, res.Record = state, id
		res.NewRevision = &revisionRef{Domain: stateDomain, Value: "1"}
		return res, err
	}
	// applied
	var id string
	var stateRev int64
	var err error
	switch {
	case p.target == nil:
		if id, err = m.insert(ctx, tx, requester, req, p, "active", "", ""); err != nil {
			return res, err
		}
		stateRev = 1
		if p.successor != "" {
			if _, err := m.transition(ctx, tx, p.successor, "ended", "superseded", "", requester+":"+req.ChangeKey); err != nil {
				return res, err
			}
		}
	case p.endReason != "":
		id = p.target.ID
		if stateRev, err = m.transition(ctx, tx, id, "ended", p.endReason, "", requester+":"+req.ChangeKey); err != nil {
			return res, err
		}
	default: // a narrowing: a new content revision, the state kept
		id = p.target.ID
		body, _ := json.Marshal(p.body)
		if err := tx.QueryRow(ctx, `UPDATE authz_record SET body = $2, revision = revision + 1,
			state_revision = state_revision + 1, last_change = $3, updated_at = now() WHERE id = $1 RETURNING state_revision`,
			id, body, requester+":"+req.ChangeKey).Scan(&stateRev); err != nil {
			return res, err
		}
	}
	rev, err := m.applied(ctx, tx, requester, req.Direction, p.recTypeOr(), id)
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
func (m *Module) insert(ctx context.Context, tx db.Tx, requester string, req request, p plan, state, endReason,
	reason string) (string, error) {
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
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`, id, p.recType, state, end, body, requester, pred,
		p.at, p.from, p.to, why, requester+":"+req.ChangeKey)
	return id, err
}

// transition moves a record to state (with its end or hold reason), advancing its state revision.
func (m *Module) transition(ctx context.Context, tx db.Tx, id, state, endReason, holdReason, change string) (int64, error) {
	var end, hold any
	if endReason != "" {
		end = endReason
	}
	if holdReason != "" {
		hold = holdReason
	}
	var rev int64
	err := tx.QueryRow(ctx, `UPDATE authz_record SET state = $2, end_reason = $3, hold_reason = $4,
		state_revision = state_revision + 1, last_change = coalesce($5, last_change), updated_at = now()
		WHERE id = $1 RETURNING state_revision`, id, state, end, hold, nullable(change)).Scan(&rev)
	return rev, err
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
