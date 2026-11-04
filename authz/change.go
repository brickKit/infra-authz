package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/brickKit/be-sdk-go/v3/audit"
	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/jackc/pgx/v5"
)

// The effect point (security 08): every change enters it as an entry, under the deployment's guard, in one
// transaction: the key's binding, the facts (facts.go), the decision table (decide.go), the writes its outcome calls
// for (enact.go) and the key's new binding. A user submits a change on the user surface; the member's own jobs
// (scheduled.go) enter under a derived key.

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
	// Release: a release of a security disposition (09a's disposition_release, release.go)
	Release *releaseIn `json:"release,omitempty"`
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
	// Basis is last_applied when the requester was judged by the source's last applied facts (security 03): the basis
	// not proven latest
	Basis string `json:"basis,omitempty"`
}

func (r *changeResult) Error() string { return r.Reason + ": " + r.Detail }

// entry is one change entering the effect point: whose key it binds (the requester's namespace, or this member's for
// a derived key), the key and the digest of its content, who the requester is, and what entered: a user's request,
// or a saved record's job.
type entry struct {
	namespace, key, digest string
	requester, trigger     string
	req                    request
	job                    *firing
	selfOnly               bool // a relinquishment (D82): only the requester's own record
}

// operation is the operation that admitted the entry, for its audit: a relinquishment, a tightening, or a change (a
// widening, a neutral change, the member's own jobs).
func (e entry) operation() string {
	switch {
	case e.selfOnly:
		return OpRelinquish
	case isDisposition(e.req.Candidate):
		return OpDispose
	case e.req.Release != nil:
		return OpRelease
	case e.req.Direction == Tighten:
		return OpTighten
	}
	return OpChange
}

// plan is what the effect point writes for each outcome of one change.
type plan struct {
	kind      string
	recType   string
	body      any // the new record's or the narrowed content
	target    *target
	endReason string   // what an applied tightening ends the target with ("": a narrowing)
	activate  bool     // a saved widening (scheduled) that takes effect
	restore   bool     // a held (uncomputable) record restored
	review    bool     // applied, partly outside its limits: to be reviewed (row 30)
	confirmed []string // the confirmations to mark used when it applies
	from, to  *time.Time
	at        *time.Time // effective_from
	successor string     // the predecessor that a new record supersedes
	// keepPredecessor: the predecessor is held by a disposition; its release ends it superseded (CP31)
	keepPredecessor bool
	// basis: the requester judged by the last applied facts (security 03); the result and the audit say so
	basis map[string]any
	// coolingOff: a protected widening the owner alone confirmed, waiting until then (cooling.go)
	coolingOff *time.Time
	// disp: a new security disposition (disposition.go); release: a disposition's release (release.go)
	disp    *plannedDisposition
	release *plannedRelease
	// whyNot: why the candidate is not contained (row 18); whyOver: why it is over a budget (rows 19, 26). The
	// rejection's detail says which dimension or budget (security 07, "见证与结果")
	whyNot, whyOver string
}

// whyFor is the detail a row's rejection adds: which dimension is not contained (row 18), which budget is exceeded
// (rows 19, 26).
func (p plan) whyFor(row int) string {
	switch {
	case row == 18 && p.whyNot != "":
		return ": " + p.whyNot
	case (row == 19 || row == 26) && p.whyOver != "":
		return ": " + p.whyOver
	}
	return ""
}

// change runs one user change at the effect point.
func (m *Module) change(ctx context.Context, requester string, req request) (changeResult, error) {
	return m.changeAs(ctx, requester, req, false)
}

// changeAs is change; selfOnly a relinquishment (D82).
func (m *Module) changeAs(ctx context.Context, requester string, req request, selfOnly bool) (changeResult, error) {
	if req.ChangeKey == "" {
		return changeResult{}, errs.New(errs.ReasonRequestInvalid, "change_key is required")
	}
	digest, err := requestDigest(requester, req)
	if err != nil {
		return changeResult{}, err
	}
	e := entry{namespace: requester, key: req.ChangeKey, digest: digest, requester: requester, trigger: ByUser, req: req,
		selfOnly: selfOnly}
	var res changeResult
	err = m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		res, _, err = m.effect(ctx, tx, e)
		return err
	})
	if err != nil {
		return changeResult{}, err
	}
	m.denied(ctx, e, res)
	return res, nil
}

// denied audits a final rejection (a key conflict is not one: nothing was decided).
func (m *Module) denied(ctx context.Context, e entry, res changeResult) {
	if res.Outcome == "rejected" && !res.Retryable && res.Reason != errs.ReasonChangeKeyConflict {
		_ = m.rt.Audit.Denial(ctx, audit.Record{Category: audit.SecurityDenial, Operation: OpChange, Outcome: audit.Denied,
			Reason: res.Reason, Actor: e.requester, Changes: map[string]any{"direction": e.req.Direction,
				"target": e.req.Target, "trigger": e.trigger, "change_key": e.key}})
	}
}

// effect is the effect point inside the caller's transaction (the job's completion, or the user's own). verdict is
// the table's (row 0 when the change was answered before the table).
func (m *Module) effect(ctx context.Context, tx db.Tx, e entry) (changeResult, verdict, error) {
	if _, err := tx.Exec(ctx, "SELECT 1 FROM authz_state FOR UPDATE"); err != nil { // the guard: one change at a time
		return changeResult{}, verdict{}, err
	}
	var bound []byte
	var boundDigest string
	f := facts{}
	err := tx.QueryRow(ctx, "SELECT result, content_digest FROM authz_change WHERE requested_by = $1 AND change_key = $2",
		e.namespace, e.key).Scan(&bound, &boundDigest)
	switch {
	case err == nil && boundDigest == e.digest:
		f.Key = keyBoundSame
	case err == nil:
		f.Key = keyBoundElse
	case !errors.Is(err, pgx.ErrNoRows):
		return changeResult{}, verdict{}, err
	}
	var p plan
	if f.Key == keyFree {
		var pre *changeResult
		if f, p, pre, err = m.factsOf(ctx, tx, e); err != nil || pre != nil {
			if pre != nil {
				pre.ChangeKey = e.key
				err = m.bindPre(ctx, tx, e, pre)
				return *pre, verdict{}, err
			}
			return changeResult{}, verdict{}, err
		}
	}
	v := decide(f)
	if v.Row == 1 { // the bound result again, with a saved record's current state (CP61)
		var res changeResult
		if err := json.Unmarshal(bound, &res); err != nil {
			return res, v, err
		}
		res, err = current(ctx, tx, res)
		return res, v, err
	}
	res, err := m.enact(ctx, tx, e, p, v)
	if err != nil {
		return res, v, err
	}
	if res.Outcome == "applied" && f.AffectsAdmins { // an admin may have become unavailable (T6e)
		if err := m.judgeAdmins(ctx, tx); err != nil {
			return res, v, err
		}
	}
	res.ChangeKey = e.key
	if binds(v, e.trigger) {
		out, _ := json.Marshal(res)
		var rec any
		if res.Record != "" {
			rec = res.Record
		}
		_, err = tx.Exec(ctx, `INSERT INTO authz_change (requested_by, change_key, content_digest, result, record)
			VALUES ($1, $2, $3, $4, $5)`, e.namespace, e.key, e.digest, out, rec)
	}
	return res, v, err
}

// current is a bound result as it stands now (security 08, CP61: a retry answers the record and its current state).
// A saved record (scheduled, awaiting confirmation) this member's own job applied or rejected since answers that job's
// result; one ended otherwise (withdrawn, cancelled, a confirmer's rejection) answers rejected; the rest as bound.
func current(ctx context.Context, tx db.Tx, res changeResult) (changeResult, error) {
	if res.Record == "" || (res.Outcome != "scheduled" && res.Outcome != "awaiting_confirmation") {
		return res, nil
	}
	key := res.ChangeKey
	var later []byte
	err := tx.QueryRow(ctx, `SELECT result FROM authz_change WHERE record = $1 AND requested_by = $2
		AND result->>'outcome' IN ('applied', 'rejected') ORDER BY created_at DESC LIMIT 1`, res.Record, ID).Scan(&later)
	switch {
	case err == nil:
		var out changeResult
		if err := json.Unmarshal(later, &out); err != nil {
			return res, err
		}
		out.ChangeKey = key
		return out, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return res, err
	}
	var state, endReason string
	if err := tx.QueryRow(ctx, "SELECT state, coalesce(end_reason, '') FROM authz_record WHERE id = $1", res.Record).
		Scan(&state, &endReason); err != nil {
		return res, err
	}
	switch state {
	case "ended":
		return changeResult{ChangeKey: key, Outcome: "rejected", Reason: errs.ReasonChangeRevisionStale, Record: res.Record,
			Detail: "the record ended (" + endReason + ") before it took effect"}, nil
	case "scheduled", "awaiting_confirmation":
		res.Outcome = state
	}
	return res, nil
}

// bindPre binds an answer given before the table when it is final: an invalid request (D77).
func (m *Module) bindPre(ctx context.Context, tx db.Tx, e entry, res *changeResult) error {
	if res.Outcome != "rejected" || res.Retryable {
		return nil
	}
	out, _ := json.Marshal(res)
	_, err := tx.Exec(ctx, `INSERT INTO authz_change (requested_by, change_key, content_digest, result)
		VALUES ($1, $2, $3, $4)`, e.namespace, e.key, e.digest, out)
	return err
}

// binds is the key table (security 08, "变更键"). A requester's key: applied, a final rejection and a saved record
// bind; processing, a retryable rejection and a tightening that waits for its confirmation do not. A derived key:
// applied and a final rejection bind; awaiting confirmation, a kept hold and processing do not; a void job binds
// nothing. A conflict (row 2) leaves the key as its first change bound it.
func binds(v verdict, trigger string) bool {
	switch v.Outcome {
	case outApplied, outAppliedReview, outRejected:
		return v.Row != 2
	case outScheduled, outAwaitingSaved:
		return trigger == ByUser
	}
	return false
}

// requestDigest is the identity of a change's content under its key: the request in canonical form (09a).
func requestDigest(requester string, req request) (string, error) {
	body, _ := json.Marshal(req)
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var v map[string]any
	_ = d.Decode(&v)
	v["requested_by"], v["trigger"] = requester, ByUser
	digest, err := canon.Digest("be.security.change_request", 1, v)
	if err != nil {
		return "", errs.New(errs.ReasonRequestInvalid, "the change cannot be encoded: "+err.Error())
	}
	return digest, nil
}

// candidateDigest is the digest a candidate carries (09a, the SDK's CandidateDigest); "" when it has none (not an
// object, a float, a null), which no request's digest equals.
func candidateDigest(recordType string, raw json.RawMessage) string {
	d, err := sdkauthz.CandidateDigest(recordType, raw)
	if err != nil {
		return ""
	}
	return d
}

// window reads a candidate's validity.
func window(w sdkauthz.Window) (*time.Time, *time.Time, error) {
	var from, to *time.Time
	if w.From != "" {
		t, err := time.Parse(time.RFC3339Nano, w.From)
		if err != nil {
			return nil, nil, errors.New("valid.from is not an instant")
		}
		from = &t
	}
	if w.Until != "" {
		t, err := time.Parse(time.RFC3339Nano, w.Until)
		if err != nil {
			return nil, nil, errors.New("valid.until is not an instant")
		}
		to = &t
	}
	if from != nil && to != nil && !to.After(*from) {
		return nil, nil, errors.New("valid.until is after valid.from")
	}
	return from, to, nil
}
