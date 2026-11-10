package effectpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	core "github.com/brickKit/infra-authz/v3/internal/core"
	employment "github.com/brickKit/infra-authz/v3/internal/employment"

	"github.com/brickKit/be-sdk-go/v3/audit"
	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/jackc/pgx/v5"
)

// errRejected carries a final rejection out of the effect point's transaction so its key is bound in a second one.
type errRejected struct{ Reason, Detail string }

func (e *errRejected) Error() string { return e.Reason + ": " + e.Detail }

func reject(reason, detail string) error {
	return &errRejected{Reason: reason, Detail: detail}
}

// applied advances the security revision and writes the security change's audit record in the same transaction.
func applied(m *core.Base, ctx context.Context, tx db.Tx, op, requester, direction, typ, id string, basis map[string]any) (int64, error) {
	if err := core.Advance(ctx, tx); err != nil {
		return 0, err
	}
	var rev int64
	if err := tx.QueryRow(ctx, "SELECT security_revision FROM authz_state").Scan(&rev); err != nil {
		return 0, err
	}
	return rev, audited(m, ctx, tx, op, requester, direction, typ, id, fmt.Sprint(rev), basis)
}

// audited writes a security change's audit record in its transaction, under the operation op that admitted it; rev is the security revision it advanced to
// ("" for a neutral change, which advances none); basis, when the requester was judged by the last applied facts:
// "basis not proven latest" with the source as the judgement saw it (security 03).
func audited(m *core.Base, ctx context.Context, tx db.Tx, op, requester, direction, typ, id, rev string, basis map[string]any) error {
	changes := map[string]any{"direction": direction}
	if rev != "" {
		changes["security_revision"] = rev
	}
	for k, v := range basis {
		changes[k] = v
	}
	_, err := m.RT.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: op,
		Outcome: audit.Succeeded, Actor: requester, Target: map[string]any{"type": typ, "id": id}, Changes: changes})
	return err
}

// within proves every candidate segment is contained in one of the unit's effective limit segments for its operation
// (security 07; no split along a dimension in this step): its scope ∩ its parents' up to the root (effective.go). The
// root contains every well-formed segment.
func within(m *core.Base, ctx context.Context, tx db.Tx, segs []sdkauthz.Segment, lim *core.Limit, grantee string) error {
	for _, s := range segs {
		r, err := resourceFor(m, ctx, tx, s.ResourceType)
		if err != nil {
			return err
		}
		if r == nil {
			reg, err := core.RegistryNow(m)
			if err != nil {
				return err
			}
			if reg.Owner("resource_type", s.ResourceType) == "" {
				// no component of this deployment owns it (a typo, a component not deployed): nothing is on its way,
				// so a final rejection that binds the key (D77)
				return reject(errs.ReasonRequestInvalid, "resource type "+s.ResourceType+" is not registered in this deployment")
			}
			// its owner is ready before its definitions are accepted (P8.24): retryable, the key stays free (D77)
			return reject(errs.ReasonDefinitionPending, "resource type "+s.ResourceType+" is not defined yet")
		}
		if err := s.Check(r); err != nil {
			return reject(errs.ReasonRequestInvalid, err.Error())
		}
		switch {
		case lim == nil:
			return reject(errs.ReasonContainmentNotProven, "the unit is not under an active unit up to the root")
		case lim.All:
			continue
		}
		if !slices.Contains(lim.Ops, s.Operation) {
			return reject(errs.ReasonContainmentNotProven, "operation "+s.Operation+" is not grantable in the unit")
		}
		var last *core.NotContained
		ok := slices.ContainsFunc(lim.Segs, func(l sdkauthz.Segment) bool {
			last = core.Contained(s, l, grantee)
			return last == nil
		})
		if !ok {
			why := "no limit segment for " + s.Operation
			if last != nil {
				why = last.Error()
			}
			return reject(errs.ReasonContainmentNotProven, why)
		}
	}
	return nil
}

func Units(m *core.Base, ctx context.Context, tx db.Tx) (map[string]core.UnitBody, error) {
	recs, err := core.Active(ctx, tx, "management_unit")
	if err != nil {
		return nil, err
	}
	out := map[string]core.UnitBody{}
	for _, r := range recs {
		var u core.UnitBody
		if err := json.Unmarshal(r.Body, &u); err != nil {
			return nil, err
		}
		u.ID = r.ID
		out[r.ID] = u
	}
	// a unit renewed or widened is a new record superseding the old (security 08): what names the old one (a child's
	// parent, a holding, a grant's governance unit) is under its active successor
	rows, err := tx.Query(ctx, `SELECT predecessor::text, id::text FROM authz_record WHERE record_type = 'management_unit'
		AND predecessor IS NOT NULL AND (state = 'active' OR end_reason = 'superseded')`)
	if err != nil {
		return nil, err
	}
	succ := map[string]string{}
	for rows.Next() {
		var pred, id string
		if err := rows.Scan(&pred, &id); err != nil {
			return nil, err
		}
		succ[pred] = id
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for pred := range succ {
		cur := pred
		for range len(succ) {
			if cur = succ[cur]; cur == "" {
				break
			}
			if u, ok := out[cur]; ok {
				out[pred] = u
				break
			}
		}
	}
	return out, nil
}

// sameUnit: two unit IDs name the same current unit.
func sameUnit(units map[string]core.UnitBody, a, b string) bool {
	ua, ok1 := units[a]
	ub, ok2 := units[b]
	return a == b || ok1 && ok2 && ua.ID == ub.ID
}

// HoldingsOf returns the units a principal holds and whether one holding makes it an authorization admin.
func HoldingsOf(ctx context.Context, tx db.Tx, principal string) ([]string, bool, error) {
	recs, err := core.Active(ctx, tx, "management_holding")
	if err != nil {
		return nil, false, err
	}
	var units []string
	admin := false
	for _, r := range recs {
		var h core.HoldingBody
		if err := json.Unmarshal(r.Body, &h); err != nil {
			return nil, false, err
		}
		if h.Holder != principal || h.BackfillPending { // awaiting a reconfirmation: not available (T9d)
			continue
		}
		if h.Appointment != "" { // bound to an appointment: by the facts last applied, until the closure ends it
			held, err := employment.HeldApplied(ctx, tx, employment.Binding{Appointment: h.Appointment, Account: h.Holder})
			if err != nil {
				return nil, false, err
			}
			if !held {
				continue
			}
		}
		units = append(units, h.Unit)
		admin = admin || h.SystemRole == "authorization_admin"
	}
	return units, admin, nil
}

func RoleTemplate(ctx context.Context, tx db.Tx, id string) ([]sdkauthz.Segment, error) {
	var body json.RawMessage
	err := tx.QueryRow(ctx, "SELECT body FROM authz_record WHERE id = $1 AND record_type = 'role_revision' AND state = 'active'",
		id).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, reject(errs.ReasonRequestInvalid, "no such active role revision")
	} else if err != nil {
		return nil, err
	}
	var r core.RoleBody
	return r.SegmentsTemplate, json.Unmarshal(body, &r)
}

// resourceFor finds a resource type among the current accepted definitions of every component.
func resourceFor(m *core.Base, ctx context.Context, tx db.Tx, typ string) (*sdkauthz.Resource, error) {
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT d.record FROM authz_component c
		JOIN authz_definition_set s ON s.component = c.component AND s.version = c.version
		JOIN authz_definition d ON d.digest = ANY(s.digests)
		WHERE d.record_type = 'be.security.resource_definition' AND d.key = $1`, typ).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	return core.ResourceOf(body), nil
}
