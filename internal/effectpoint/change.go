package effectpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	"github.com/brickKit/be-sdk-go/v3/audit"
	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/evidence"
	"github.com/jackc/pgx/v5"
)

// The effect point (security 08): every change enters it as an entry, under the deployment's guard, in one
// transaction: the key's binding, the facts (facts.go), the decision table (decide.go), the writes its outcome calls
// for (enact.go) and the key's new binding. A user submits a change on the user surface; the member's own jobs
// (scheduled.go) enter under a derived key.

// Request is be.security.change_request (security 09a) as a user submits it: requested_by and trigger are not in it,
// the effect point takes them from the call (the token's subject; the user surface is the user trigger).
type Request struct {
	ChangeKey             string          `json:"change_key"`
	Direction             string          `json:"direction"`             // widen, tighten, neutral
	Termination           string          `json:"termination,omitempty"` // withdraw, reject, cancel: ending a record not yet effective
	Target                string          `json:"target,omitempty"`
	ExpectedStateRevision *RevisionRef    `json:"expected_state_revision,omitempty"`
	ExpectedRevision      *RevisionRef    `json:"expected_revision,omitempty"`
	Candidate             json.RawMessage `json:"candidate,omitempty"`
	CandidateDigest       string          `json:"candidate_digest,omitempty"`
	EffectiveFrom         string          `json:"effective_from,omitempty"`
	ActingAs              string          `json:"acting_as,omitempty"`
	ConfirmationIDs       []string        `json:"confirmation_ids,omitempty"`
	Reason                string          `json:"reason,omitempty"`
	// Release: a release of a security disposition (09a's disposition_release, release.go)
	Release *ReleaseIn `json:"release,omitempty"`
}

// RevisionRef is 09a's RevisionRef as this member numbers a record: its state revision and its content revision.
type RevisionRef struct {
	Domain string `json:"domain"`
	Value  string `json:"value"`
}

const (
	StateDomain   = "authz.record.state"
	ContentDomain = "authz.record.revision"
)

// ChangeResult is be.security.change_result; unbound answers a query by a key nothing bound.
type ChangeResult struct {
	ChangeKey         string        `json:"change_key"`
	Outcome           string        `json:"outcome"` // applied, rejected, processing, awaiting_confirmation, scheduled, held_kept, unbound
	Reason            string        `json:"reason,omitempty"`
	Detail            string        `json:"detail,omitempty"`
	Retryable         bool          `json:"-"` // a rejection that keeps the key free
	Record            string        `json:"record,omitempty"`
	NewRevision       *RevisionRef  `json:"new_revision,omitempty"`
	SecurityRevisions []RevisionRef `json:"security_revisions,omitempty"`
	// Basis is last_applied when the requester was judged by the source's last applied facts (security 03): the basis
	// not proven latest
	Basis string `json:"basis,omitempty"`
}

func (r *ChangeResult) Error() string { return r.Reason + ": " + r.Detail }

// Entry is one change entering the effect point: whose key it binds (the requester's namespace, or this member's for
// a derived key), the key and the digest of its content, who the requester is, and what entered: a user's request,
// or a saved record's job.
type Entry struct {
	Namespace, Key, Digest string  `json:"-"`
	Requester, Trigger     string  `json:"-"`
	Req                    Request `json:"-"`
	job                    *firing
	selfOnly               bool // a relinquishment (D82): only the requester's own record
	PlanItem               bool `json:"-"` // a plan's item: a target moved since the preview is row 17, not row 3 (planrun.go)
	// replay is the evidence record's object of a full recovery's replay (assembly protocol 15, 6.3; replay.go): the
	// business preconditions are not decided again, a new record takes this identity, no evidence is written and the
	// last admin is judged after the whole replay (6.5), not here.
	Replay string `json:"-"`
}

// operation is the operation that admitted the entry, for its audit: a relinquishment, a tightening, or a change (a
// widening, a neutral change, the member's own jobs).
func (e Entry) operation() string {
	switch {
	case e.selfOnly:
		return core.OpRelinquish
	case IsDisposition(e.Req.Candidate):
		return core.OpDispose
	case e.Req.Release != nil:
		return core.OpRelease
	case e.Req.Direction == core.Tighten:
		return core.OpTighten
	}
	return core.OpChange
}

// plan is what the effect point writes for each outcome of one change.
type plan struct {
	kind      string
	recType   string
	body      any // the new record's or the narrowed content
	target    *Target
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
func change(m *core.Base, ctx context.Context, requester string, req Request) (ChangeResult, error) {
	return changeAs(m, ctx, requester, req, false)
}

// changeAs is change; selfOnly a relinquishment (D82).
func changeAs(m *core.Base, ctx context.Context, requester string, req Request, selfOnly bool) (ChangeResult, error) {
	if req.ChangeKey == "" {
		return ChangeResult{}, errs.New(errs.ReasonRequestInvalid, "change_key is required")
	}
	digest, err := RequestDigest(requester, req)
	if err != nil {
		return ChangeResult{}, err
	}
	e := Entry{Namespace: requester, Key: req.ChangeKey, Digest: digest, Requester: requester, Trigger: core.ByUser, Req: req,
		selfOnly: selfOnly}
	// a tightening's intent goes to the evidence before the effect point (assembly protocol 15, P12.16): never held
	// back by it; the conclusion follows in the effect point's transaction, or cancelled when nothing applied
	// A key already bound answers its bound result (row 1) or a conflict: no intent, which would only be cancelled. The
	// look is without the guard; a key bound after it still cancels its intent, as before.
	var pending *evidence.Pending
	bound := false
	if req.Direction == core.Tighten && m.RT.Evidence != nil {
		if err := m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
			return tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM authz_change WHERE requested_by = $1 AND change_key = $2)",
				e.Namespace, e.Key).Scan(&bound)
		}); err != nil {
			return ChangeResult{}, err
		}
	}
	if req.Direction == core.Tighten && m.RT.Evidence != nil && !bound {
		if pending, err = m.RT.Evidence.Intent(ctx, "security_tightening", "", evidence.Object{Type: core.Records,
			ID: req.Target, Version: RevisionValue(req.ExpectedStateRevision)}, EvidenceChange(requester, req)); err != nil {
			return ChangeResult{}, err
		}
	}
	var res ChangeResult
	concluded := false
	err = m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var v core.Verdict
		concluded = false
		if res, v, err = Effect(m, ctx, tx, e); err != nil {
			return err
		}
		if pending != nil && res.Outcome == "applied" && v.Row != 1 { // applied now, not a bound result again
			concluded = true
			return pending.Effective(ctx, tx)
		}
		return nil
	})
	if pending != nil && !concluded {
		if cerr := pending.Cancelled(ctx); cerr != nil {
			m.RT.Logger.Error("a tightening's cancelled conclusion could not be queued", "id", pending.ID, "error", cerr.Error())
		}
	}
	if err != nil {
		return ChangeResult{}, err
	}
	Denied(m, ctx, e, res)
	return res, nil
}

// RevisionValue is a revision reference's value, "" for none.
func RevisionValue(r *RevisionRef) string {
	if r == nil {
		return ""
	}
	return r.Value
}

// EvidenceChange is what a change's evidence records: the change itself (P12.9), never the resulting state; with the
// candidate and the effective time, so that a full recovery's replay applies it again (replay.go).
func EvidenceChange(requester string, req Request) map[string]any {
	c := map[string]any{"direction": req.Direction, "requested_by": requester, "change_key": req.ChangeKey}
	if req.EffectiveFrom != "" {
		c["effective_from"] = req.EffectiveFrom
	}
	if req.Termination != "" {
		c["termination"] = req.Termination
	}
	if req.Target != "" {
		c["target"] = req.Target
	}
	if len(req.Candidate) > 0 { // the narrowed content or the disposition itself: what a replay applies again
		d := json.NewDecoder(bytes.NewReader(req.Candidate))
		d.UseNumber()
		var v any
		if d.Decode(&v) == nil {
			c["candidate"] = v
		}
	}
	return c
}

// Denied audits a final rejection (a key conflict is not one: nothing was decided).
func Denied(m *core.Base, ctx context.Context, e Entry, res ChangeResult) {
	if res.Outcome == "rejected" && !res.Retryable && res.Reason != errs.ReasonChangeKeyConflict {
		_ = m.RT.Audit.Denial(ctx, audit.Record{Category: audit.SecurityDenial, Operation: core.OpChange, Outcome: audit.Denied,
			Reason: res.Reason, Actor: e.Requester, Changes: map[string]any{"direction": e.Req.Direction,
				"target": e.Req.Target, "trigger": e.Trigger, "change_key": e.Key}})
	}
}

// Effect is the effect point inside the caller's transaction (the job's completion, or the user's own). verdict is
// the table's (row 0 when the change was answered before the table).
func Effect(m *core.Base, ctx context.Context, tx db.Tx, e Entry) (ChangeResult, core.Verdict, error) {
	if _, err := tx.Exec(ctx, "SELECT 1 FROM authz_state FOR UPDATE"); err != nil { // the guard: one change at a time
		return ChangeResult{}, core.Verdict{}, err
	}
	var bound []byte
	var boundDigest string
	f := core.Facts{}
	err := tx.QueryRow(ctx, "SELECT result, content_digest FROM authz_change WHERE requested_by = $1 AND change_key = $2",
		e.Namespace, e.Key).Scan(&bound, &boundDigest)
	switch {
	case err == nil && boundDigest == e.Digest:
		f.Key = core.KeyBoundSame
	case err == nil:
		f.Key = core.KeyBoundElse
	case !errors.Is(err, pgx.ErrNoRows):
		return ChangeResult{}, core.Verdict{}, err
	}
	var p plan
	if f.Key == core.KeyFree {
		var pre *ChangeResult
		if f, p, pre, err = factsOf(m, ctx, tx, e); err == nil && pre == nil && e.Replay != "" {
			f = core.ReplayFacts(f)
		}
		if err != nil || pre != nil {
			if pre != nil {
				pre.ChangeKey = e.Key
				err = bindPre(m, ctx, tx, e, pre)
				return *pre, core.Verdict{}, err
			}
			return ChangeResult{}, core.Verdict{}, err
		}
	}
	v := core.Decide(f)
	if v.Row == 1 { // the bound result again, with a saved record's current state (CP61)
		var res ChangeResult
		if err := json.Unmarshal(bound, &res); err != nil {
			return res, v, err
		}
		res, err = current(ctx, tx, res)
		return res, v, err
	}
	res, err := enact(m, ctx, tx, e, p, v)
	if err != nil {
		return res, v, err
	}
	if res.Outcome == "applied" && (e.Req.Direction == core.Widen || e.Req.Direction == "release") && m.RT.Evidence != nil &&
		e.Replay == "" {
		// a widening (a release restores access too), in its transaction, with what a replay applies again
		c := EvidenceChange(e.Requester, e.Req)
		c["direction"], c["trigger"], c["change_key"] = core.Widen, e.Trigger, e.Key
		if r := e.Req.Release; r != nil { // a release: which disposition and the signals it removes (T13b)
			c["direction"] = "release"
			c["release"] = map[string]any{"disposition": r.Disposition, "signal_refs": NonNil(r.SignalRefs)}
		}
		if _, err := m.RT.Evidence.General(ctx, tx, "security_widening", "", evidence.Object{Type: core.Records, ID: res.Record,
			Version: RevisionValue(res.NewRevision)}, c); err != nil {
			return res, v, err
		}
	}
	if res.Outcome == "applied" && f.AffectsAdmins && e.Replay == "" { // an admin may have become unavailable (T6e)
		if err := JudgeAdmins(m, ctx, tx); err != nil {
			return res, v, err
		}
	}
	res.ChangeKey = e.Key
	if binds(v, e.Trigger) {
		out, _ := json.Marshal(res)
		var rec any
		if res.Record != "" {
			rec = res.Record
		}
		_, err = tx.Exec(ctx, `INSERT INTO authz_change (requested_by, change_key, content_digest, result, record)
			VALUES ($1, $2, $3, $4, $5)`, e.Namespace, e.Key, e.Digest, out, rec)
	}
	return res, v, err
}

// current is a bound result as it stands now (security 08, CP61: a retry answers the record and its current state).
// A saved record (scheduled, awaiting confirmation) this member's own job applied or rejected since answers that job's
// result; one ended otherwise (withdrawn, cancelled, a confirmer's rejection) answers rejected; the rest as bound.
func current(ctx context.Context, tx db.Tx, res ChangeResult) (ChangeResult, error) {
	if res.Record == "" || (res.Outcome != "scheduled" && res.Outcome != "awaiting_confirmation") {
		return res, nil
	}
	key := res.ChangeKey
	var later []byte
	err := tx.QueryRow(ctx, `SELECT result FROM authz_change WHERE record = $1 AND requested_by = $2
		AND result->>'outcome' IN ('applied', 'rejected') ORDER BY created_at DESC LIMIT 1`, res.Record, core.ID).Scan(&later)
	switch {
	case err == nil:
		var out ChangeResult
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
		return ChangeResult{ChangeKey: key, Outcome: "rejected", Reason: errs.ReasonChangeRevisionStale, Record: res.Record,
			Detail: "the record ended (" + endReason + ") before it took effect"}, nil
	case "scheduled", "awaiting_confirmation":
		res.Outcome = state
	}
	return res, nil
}

// bindPre binds an answer given before the table when it is final: an invalid request (D77).
func bindPre(m *core.Base, ctx context.Context, tx db.Tx, e Entry, res *ChangeResult) error {
	if res.Outcome != "rejected" || res.Retryable {
		return nil
	}
	out, _ := json.Marshal(res)
	_, err := tx.Exec(ctx, `INSERT INTO authz_change (requested_by, change_key, content_digest, result)
		VALUES ($1, $2, $3, $4)`, e.Namespace, e.Key, e.Digest, out)
	return err
}

// binds is the key table (security 08, "变更键"). A requester's key: applied, a final rejection and a saved record
// bind; processing, a retryable rejection and a tightening that waits for its confirmation do not. A derived key:
// applied and a final rejection bind; awaiting confirmation, a kept hold and processing do not; a void job binds
// nothing. A conflict (row 2) leaves the key as its first change bound it.
func binds(v core.Verdict, trigger string) bool {
	switch v.Outcome {
	case core.OutApplied, core.OutAppliedReview, core.OutRejected:
		return v.Row != 2
	case core.OutScheduled, core.OutAwaitingSaved:
		return trigger == core.ByUser
	}
	return false
}

// RequestDigest is the identity of a change's content under its key: the request in canonical form (09a).
func RequestDigest(requester string, req Request) (string, error) {
	body, _ := json.Marshal(req)
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var v map[string]any
	_ = d.Decode(&v)
	v["requested_by"], v["trigger"] = requester, core.ByUser
	digest, err := canon.Digest("be.security.change_request", 1, v)
	if err != nil {
		return "", errs.New(errs.ReasonRequestInvalid, "the change cannot be encoded: "+err.Error())
	}
	return digest, nil
}

// CandidateDigest is the digest a candidate carries (09a, the SDK's CandidateDigest); "" when it has none (not an
// object, a float, a null), which no request's digest equals.
func CandidateDigest(recordType string, raw json.RawMessage) string {
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
