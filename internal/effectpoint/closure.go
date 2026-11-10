package effectpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	core "github.com/brickKit/infra-authz/v3/internal/core"
	employment "github.com/brickKit/infra-authz/v3/internal/employment"

	"github.com/brickKit/be-sdk-go/v3/audit"
	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/projection"
	"github.com/brickKit/be-sdk-go/v3/work"
	"github.com/jackc/pgx/v5"
)

// The closure job (security 08, "影响闭包"): after a source tightens, the view has already narrowed (effective.go);
// the job only keeps the books. It finds the affected records through the dependency index and moves each by what
// its sources now give: ended (source_ended) when a source ended, ended (source_narrowed) when nothing is left, held
// (uncomputable) when the intersection cannot be computed, and the review flag when partly outside. These moves
// advance the state revision but take no security revision (no access changes) and are not change requests. The
// job is repeatable: every judgement is made again from the sources as they stand.

// JobClosure is one source's closure: the records depending on it.
const JobClosure = "infra.authz.closure"

// source is one source of a record (09a's SourceRef): its kind, the record or principal, and its role.
type source struct{ Kind, Ref, Role string }

// sourcesOf follows from a record's content.
func sourcesOf(recType string, body json.RawMessage) []source {
	var b struct {
		GovernanceUnit string `json:"governance_unit"`
		RoleRevision   string `json:"role_revision"`
		Grantee        string `json:"grantee"`
		Parent         string `json:"parent"`
		Unit           string `json:"unit"`
		Holder         string `json:"holder"`
		Appointment    string `json:"appointment"`
	}
	_ = json.Unmarshal(body, &b)
	var out []source
	add := func(kind, ref, role string) {
		if ref != "" {
			out = append(out, source{kind, ref, role})
		}
	}
	switch recType {
	case "grant":
		add("management_unit", b.GovernanceUnit, "ceiling")
		add("role_revision", b.RoleRevision, "permission_basis")
		add("account", b.Grantee, "eligibility")
		add("appointment", b.Appointment, "eligibility")
	case "management_unit":
		add("management_unit", b.Parent, "ceiling")
	case "management_holding":
		add("management_unit", b.Unit, "ceiling")
		add("account", b.Holder, "eligibility")
		add("appointment", b.Appointment, "eligibility")
	}
	return out
}

// IndexSources writes a new record's sources into the dependency index, in the record's transaction.
func IndexSources(ctx context.Context, tx db.Tx, id, recType string, body json.RawMessage) error {
	for _, s := range sourcesOf(recType, body) {
		if _, err := tx.Exec(ctx, `INSERT INTO authz_dependency (record, kind, ref, role) VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING`, id, s.Kind, s.Ref, s.Role); err != nil {
			return err
		}
	}
	return nil
}

// closing is a closure job's argument.
type closing struct {
	Kind string `json:"kind"`
	Ref  string `json:"ref"`
}

// CloseAfter registers the closure of a source that changed, in the change's transaction.
func CloseAfter(m *core.Base, ctx context.Context, tx db.Tx, kind, ref string) error {
	_, err := m.RT.Work.Enqueue(ctx, tx, JobClosure, closing{Kind: kind, Ref: ref})
	return err
}

// dependentTypes are the record types a source kind can be a source of (the scan when its index is not complete).
var dependentTypes = map[string][]string{
	"management_unit": {"grant", "management_unit", "management_holding"},
	"role_revision":   {"grant"},
	"account":         {"grant", "management_holding"},
	"appointment":     {"grant", "management_holding"},
}

// Closure runs one source's closure under the deployment's guard.
func Closure(m *core.Base, ctx context.Context, r *work.Run) error {
	var a closing
	if err := json.Unmarshal(r.Args, &a); err != nil || dependentTypes[a.Kind] == nil {
		return work.Permanent(fmt.Errorf("not a closure: %s", r.Args))
	}
	err := r.Complete(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT 1 FROM authz_state FOR UPDATE"); err != nil {
			return err
		}
		w, err := World(m, ctx, tx)
		if err != nil {
			return err
		}
		if a.Kind == "account" {
			ended, provable, err := AccountEnded(m, ctx, tx, a.Ref)
			if err != nil {
				return err
			}
			if !provable { // the books wait for the source to prove it (the view already does without it)
				return errAccountUnprovable
			}
			w.Ended[a.Ref] = ended
		}
		ids, scanned, err := dependents(m, ctx, tx, a, w)
		if err != nil {
			return err
		}
		if a.Kind == "appointment" { // the appointment ended, or the account no longer linked to its employee
			if err := unbound(m, ctx, tx, a.Ref, ids, &w); err != nil {
				return err
			}
		}
		for _, id := range ids {
			if err := KeepBooks(m, ctx, tx, w, id, !scanned); err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, errAccountUnprovable) || errors.Is(err, errBindingUnprovable) {
		return work.Wait(err)
	}
	return err
}

var (
	errAccountUnprovable = errors.New("the account's status cannot be proven yet")
	errBindingUnprovable = errors.New("the appointment or the link cannot be proven yet")
)

// unbound judges the bindings of an appointment's dependents (security 04): the books wait for the employee source
// to prove each.
func unbound(m *core.Base, ctx context.Context, tx db.Tx, appointment string, ids []string, w *Sources) error {
	w.Unbound = map[employment.Binding]bool{}
	for _, id := range ids {
		var account string
		if err := tx.QueryRow(ctx, "SELECT coalesce(body->>'grantee', body->>'holder', '') FROM authz_record WHERE id = $1",
			id).Scan(&account); err != nil {
			return err
		}
		b := employment.Binding{Appointment: appointment, Account: account}
		ended, provable, err := employment.Ended(m, ctx, tx, b)
		if err != nil {
			return err
		}
		if !provable {
			return errBindingUnprovable
		}
		w.Unbound[b] = ended
	}
	return nil
}

// AccountEnded: the identity source proves the account ended as a source (security 08's closure: an account
// disabled, or no longer there). A frozen account, or one disabled with a security mark, is an identity-side
// disposition (it holds, it ends nothing: T6); provable false when the source cannot prove it now.
func AccountEnded(m *core.Base, ctx context.Context, tx db.Tx, principal string) (ended, provable bool, err error) {
	j, err := m.Accounts.JudgeMany(ctx, tx, map[string][]string{principal: {principal}}, m.SrcHigh)
	if err != nil {
		return false, false, err
	}
	switch jd := j.Records[principal]; jd.Verdict {
	case projection.ProvablyAbsent:
		return true, true, nil
	case projection.Usable:
		var rec struct {
			Status       string `json:"status"`
			SecurityMark string `json:"security_mark"`
		}
		if err := json.Unmarshal(jd.Data, &rec); err != nil {
			return false, false, err
		}
		mark := rec.SecurityMark == "compromised" || rec.SecurityMark == "suspicious"
		return rec.Status == "disabled" && !mark, true, nil
	}
	return false, false, nil
}

// dependents are the records a source's change may affect: by the index, or, when the index of its kind is not
// complete, every record of the types it can be a source of, and the whole domain is marked for review (security
// 08: never "nobody is affected" on an index that cannot say).
// scanned: the index could not say, every record of those types is here, so the closure does not go on to dependent
// units' own closures (they are in the scan already; going on would scan again for each of them).
func dependents(m *core.Base, ctx context.Context, tx db.Tx, a closing, w Sources) (ids []string, scanned bool, err error) {
	refs := []string{a.Ref} // a unit: every record that is the same current unit (superseded ones included)
	if a.Kind == "management_unit" {
		for id := range w.units {
			if id != a.Ref && sameUnit(w.units, id, a.Ref) {
				refs = append(refs, id)
			}
		}
	}
	var complete bool
	err = tx.QueryRow(ctx, "SELECT complete FROM authz_dependency_index WHERE kind = $1", a.Kind).Scan(&complete)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}
	var rows pgx.Rows
	if complete {
		rows, err = tx.Query(ctx, `SELECT d.record::text FROM authz_dependency d JOIN authz_record r ON r.id = d.record
			WHERE d.kind = $1 AND d.ref = ANY($2) AND r.state IN ('active', 'held') ORDER BY d.record`, a.Kind, refs)
	} else {
		if _, err := tx.Exec(ctx, `INSERT INTO authz_review_domain (kind, ref) VALUES ($1, $2)
			ON CONFLICT (kind, ref) DO UPDATE SET marked_at = now()`, a.Kind, a.Ref); err != nil {
			return nil, false, err
		}
		m.RT.Logger.Warn("the dependency index is not complete: the whole source domain is to be reviewed",
			"kind", a.Kind, "ref", a.Ref)
		rows, err = tx.Query(ctx, `SELECT id::text FROM authz_record WHERE state IN ('active', 'held')
			AND record_type = ANY($1) ORDER BY id`, dependentTypes[a.Kind])
	}
	if err != nil {
		return nil, false, err
	}
	ids, err = pgx.CollectRows(rows, pgx.RowTo[string])
	return ids, !complete, err
}

// Sources is what the books are kept against: the active units with their effective limits, and the active role
// revisions.
type Sources struct {
	units  map[string]core.UnitBody
	limits *core.Limits
	roles  map[string]bool
	Ended  map[string]bool `json:"-"` // accounts proven ended (an account's closure)
	// Unbound: bindings proven over (an appointment's closure): the appointment ended or the account unlinked
	Unbound map[employment.Binding]bool `json:"-"`
}

func World(m *core.Base, ctx context.Context, tx db.Tx) (Sources, error) {
	units, err := Units(m, ctx, tx)
	if err != nil {
		return Sources{}, err
	}
	roles, err := core.Active(ctx, tx, "role_revision")
	if err != nil {
		return Sources{}, err
	}
	w := Sources{units: units, limits: core.NewLimits(units), roles: map[string]bool{}, Ended: map[string]bool{}}
	for _, r := range roles {
		w.roles[r.ID] = true
	}
	return w, nil
}

// verdict of the books for one record.
type booked struct {
	state, endReason, holdReason string // "": the state stays
	review                       bool
}

// assess judges one record against its sources (security 08's closure table).
func assess(t *Target, w Sources) booked {
	switch t.Type {
	case "grant":
		var b core.GrantBody
		_ = json.Unmarshal(t.Body, &b)
		if b.RoleRevision != "" && !w.roles[b.RoleRevision] || w.Ended[b.Grantee] ||
			w.Unbound[employment.Binding{Appointment: b.Appointment, Account: b.Grantee}] {
			return booked{state: "ended", endReason: "source_ended"}
		}
		return assessWithin(w, b.GovernanceUnit, b.Segments, b.Grantee)
	case "management_unit":
		var b core.UnitBody
		_ = json.Unmarshal(t.Body, &b)
		if b.Root {
			return booked{}
		}
		return assessWithin(w, b.Parent, b.ManagedScope, "")
	case "management_holding":
		var b core.HoldingBody
		_ = json.Unmarshal(t.Body, &b)
		if w.limits.Of(b.Unit) == nil || w.Ended[b.Holder] || w.Unbound[employment.Binding{Appointment: b.Appointment, Account: b.Holder}] {
			return booked{state: "ended", endReason: "source_ended"}
		}
	}
	return booked{}
}

// assessWithin judges segments within a unit's effective limit: the unit gone, nothing left, not computable, or
// partly outside (review).
func assessWithin(w Sources, unit string, segs []sdkauthz.Segment, grantee string) booked {
	lim := w.limits.OfFor(unit, grantee)
	switch {
	case lim == nil:
		return booked{state: "ended", endReason: "source_ended"}
	case lim.All:
		return booked{}
	case !lim.Computable(segs):
		return booked{state: "held", holdReason: "uncomputable"}
	case len(lim.Cut(segs, grantee)) == 0:
		return booked{state: "ended", endReason: "source_narrowed"}
	}
	return booked{review: !lim.Covers(segs, grantee)}
}

// KeepBooks moves one record by its assessment; a unit's closure goes on to its own dependents (cascade).
func KeepBooks(m *core.Base, ctx context.Context, tx db.Tx, w Sources, id string, cascade bool) error {
	t, err := LockTarget(ctx, tx, id)
	if err != nil || t == nil || (t.State != "active" && t.State != "held") {
		return err
	}
	v := assess(t, w)
	switch {
	case v.state == "held" && t.State == "held": // held already, still not computable
	case v.state == "" && t.State == "held" && (t.HoldReason == "uncomputable" || t.HoldReason == "restore_pending"):
		// computable again: its restore is the effect point's, under a derived key with this state revision
		if _, err := m.RT.Work.Enqueue(ctx, tx, JobDue, firing{Record: id, StateRevision: t.StateRevision,
			Trigger: TriggerRestore}); err != nil {
			return err
		}
	case v.state != "":
		if _, err := Transition(m, ctx, tx, id, v.state, v.endReason, v.holdReason, "", ""); err != nil {
			return err
		}
		if t.Type == "management_holding" { // an admin may have become unavailable (T6e)
			if err := JudgeAdmins(m, ctx, tx); err != nil {
				return err
			}
		}
		if _, err := m.RT.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: core.OpChange,
			Outcome: audit.Succeeded, Actor: core.ID, Target: map[string]any{"type": t.Type, "id": id},
			Changes: map[string]any{"closure": v.state, "reason": v.endReason + v.holdReason}}); err != nil {
			return err
		}
	default:
		if _, err := tx.Exec(ctx, "UPDATE authz_record SET review = $2 WHERE id = $1 AND review <> $2", id, v.review); err != nil {
			return err
		}
	}
	if t.Type == "management_unit" && cascade {
		return CloseAfter(m, ctx, tx, t.Type, id) // its effective limit moved with its parent's
	}
	return nil
}

// JobExpiry ends a record when its validity ends (security 08: access stops at evaluation already; the state is the
// closure's bookkeeping): a timed item due at valid_until, registered with the record (P7.24).
const JobExpiry = "infra.authz.expiry"

type expiring struct {
	Record string `json:"record"`
}

// expireAt registers a record's expiry, in the record's transaction.
func expireAt(m *core.Base, ctx context.Context, tx db.Tx, id string, until *time.Time) error {
	if until == nil {
		return nil
	}
	_, err := m.RT.Work.EnqueueAt(ctx, tx, JobExpiry, expiring{Record: id}, *until)
	return err
}

func Expiry(m *core.Base, ctx context.Context, r *work.Run) error {
	var a expiring
	if err := json.Unmarshal(r.Args, &a); err != nil {
		return work.Permanent(fmt.Errorf("not an expiry: %s", r.Args))
	}
	return r.Complete(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT 1 FROM authz_state FOR UPDATE"); err != nil {
			return err
		}
		var due bool
		err := tx.QueryRow(ctx, `SELECT valid_until <= now() FROM authz_record WHERE id = $1 AND state IN ('active', 'held')
			AND valid_until IS NOT NULL FOR UPDATE`, a.Record).Scan(&due)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !due {
			return nil // ended meanwhile, or not yet (never earlier than its validity)
		}
		if err != nil {
			return err
		}
		if _, err := Transition(m, ctx, tx, a.Record, "ended", "expired", "", "", ""); err != nil {
			return err
		}
		_, err = m.RT.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: core.OpChange,
			Outcome: audit.Succeeded, Actor: core.ID, Target: map[string]any{"id": a.Record},
			Changes: map[string]any{"closure": "ended", "reason": "expired"}})
		return err
	})
}
