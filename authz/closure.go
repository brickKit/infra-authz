package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/brickKit/be-sdk-go/v3/audit"
	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/db"
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
	case "management_unit":
		add("management_unit", b.Parent, "ceiling")
	case "management_holding":
		add("management_unit", b.Unit, "ceiling")
		add("account", b.Holder, "eligibility")
	}
	return out
}

// indexSources writes a new record's sources into the dependency index, in the record's transaction.
func indexSources(ctx context.Context, tx db.Tx, id, recType string, body json.RawMessage) error {
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

// closeAfter registers the closure of a source that changed, in the change's transaction.
func (m *Module) closeAfter(ctx context.Context, tx db.Tx, kind, ref string) error {
	_, err := m.rt.Work.Enqueue(ctx, tx, JobClosure, closing{Kind: kind, Ref: ref})
	return err
}

// dependentTypes are the record types a source kind can be a source of (the scan when its index is not complete).
var dependentTypes = map[string][]string{
	"management_unit": {"grant", "management_unit", "management_holding"},
	"role_revision":   {"grant"},
	"account":         {"grant", "management_holding"},
}

// closure runs one source's closure under the deployment's guard.
func (m *Module) closure(ctx context.Context, r *work.Run) error {
	var a closing
	if err := json.Unmarshal(r.Args, &a); err != nil || dependentTypes[a.Kind] == nil {
		return work.Permanent(fmt.Errorf("not a closure: %s", r.Args))
	}
	return r.Complete(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT 1 FROM authz_state FOR UPDATE"); err != nil {
			return err
		}
		w, err := m.world(ctx, tx)
		if err != nil {
			return err
		}
		ids, err := m.dependents(ctx, tx, a, w)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if err := m.keepBooks(ctx, tx, w, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// dependents are the records a source's change may affect: by the index, or, when the index of its kind is not
// complete, every record of the types it can be a source of, and the whole domain is marked for review (security
// 08: never "nobody is affected" on an index that cannot say).
func (m *Module) dependents(ctx context.Context, tx db.Tx, a closing, w sources) ([]string, error) {
	refs := []string{a.Ref} // a unit: every record that is the same current unit (superseded ones included)
	if a.Kind == "management_unit" {
		for id := range w.units {
			if id != a.Ref && sameUnit(w.units, id, a.Ref) {
				refs = append(refs, id)
			}
		}
	}
	var complete bool
	err := tx.QueryRow(ctx, "SELECT complete FROM authz_dependency_index WHERE kind = $1", a.Kind).Scan(&complete)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	var rows pgx.Rows
	if complete {
		rows, err = tx.Query(ctx, `SELECT d.record::text FROM authz_dependency d JOIN authz_record r ON r.id = d.record
			WHERE d.kind = $1 AND d.ref = ANY($2) AND r.state IN ('active', 'held') ORDER BY d.record`, a.Kind, refs)
	} else {
		if _, err := tx.Exec(ctx, `INSERT INTO authz_review_domain (kind, ref) VALUES ($1, $2)
			ON CONFLICT (kind, ref) DO UPDATE SET marked_at = now()`, a.Kind, a.Ref); err != nil {
			return nil, err
		}
		m.rt.Logger.Warn("the dependency index is not complete: the whole source domain is to be reviewed",
			"kind", a.Kind, "ref", a.Ref)
		rows, err = tx.Query(ctx, `SELECT id::text FROM authz_record WHERE state IN ('active', 'held')
			AND record_type = ANY($1) ORDER BY id`, dependentTypes[a.Kind])
	}
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// sources is what the books are kept against: the active units with their effective limits, and the active role
// revisions.
type sources struct {
	units  map[string]unitBody
	limits *limits
	roles  map[string]bool
}

func (m *Module) world(ctx context.Context, tx db.Tx) (sources, error) {
	units, err := m.units(ctx, tx)
	if err != nil {
		return sources{}, err
	}
	roles, err := active(ctx, tx, "role_revision")
	if err != nil {
		return sources{}, err
	}
	w := sources{units: units, limits: newLimits(units), roles: map[string]bool{}}
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
func assess(t *target, w sources) booked {
	switch t.Type {
	case "grant":
		var b grantBody
		_ = json.Unmarshal(t.Body, &b)
		if b.RoleRevision != "" && !w.roles[b.RoleRevision] {
			return booked{state: "ended", endReason: "source_ended"}
		}
		return assessWithin(w, b.GovernanceUnit, b.Segments, b.Grantee)
	case "management_unit":
		var b unitBody
		_ = json.Unmarshal(t.Body, &b)
		if b.Root {
			return booked{}
		}
		return assessWithin(w, b.Parent, b.ManagedScope, "")
	case "management_holding":
		var b holdingBody
		_ = json.Unmarshal(t.Body, &b)
		if w.limits.of(b.Unit) == nil {
			return booked{state: "ended", endReason: "source_ended"}
		}
	}
	return booked{}
}

// assessWithin judges segments within a unit's effective limit: the unit gone, nothing left, not computable, or
// partly outside (review).
func assessWithin(w sources, unit string, segs []sdkauthz.Segment, grantee string) booked {
	lim := w.limits.of(unit)
	switch {
	case lim == nil:
		return booked{state: "ended", endReason: "source_ended"}
	case lim.all:
		return booked{}
	case !lim.computable(segs):
		return booked{state: "held", holdReason: "uncomputable"}
	case len(lim.cut(segs, grantee)) == 0:
		return booked{state: "ended", endReason: "source_narrowed"}
	}
	return booked{review: !lim.covers(segs, grantee)}
}

// keepBooks moves one record by its assessment; a unit's closure goes on to its own dependents.
func (m *Module) keepBooks(ctx context.Context, tx db.Tx, w sources, id string) error {
	t, err := lockTarget(ctx, tx, id)
	if err != nil || t == nil || (t.State != "active" && t.State != "held") {
		return err
	}
	v := assess(t, w)
	switch {
	case v.state == "held" && t.State == "held": // held already (its restore is the effect point's)
	case v.state != "":
		if _, err := m.transition(ctx, tx, id, v.state, v.endReason, v.holdReason, "", ""); err != nil {
			return err
		}
		if _, err := m.rt.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: OpChange,
			Outcome: audit.Succeeded, Actor: ID, Target: map[string]any{"type": t.Type, "id": id},
			Changes: map[string]any{"closure": v.state, "reason": v.endReason + v.holdReason}}); err != nil {
			return err
		}
	default:
		if _, err := tx.Exec(ctx, "UPDATE authz_record SET review = $2 WHERE id = $1 AND review <> $2", id, v.review); err != nil {
			return err
		}
	}
	if t.Type == "management_unit" {
		return m.closeAfter(ctx, tx, t.Type, id) // its effective limit moved with its parent's
	}
	return nil
}
