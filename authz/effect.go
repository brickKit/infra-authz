package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/brickKit/be-sdk-go/v3/audit"
	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/jackc/pgx/v5"
)

// change is one request to the effect point (security 08, "生效点"; the action names are this step's).
type change struct {
	ChangeKey string `json:"change_key"`
	Action    string `json:"action"` // unit.create, holding.create, holding.end, role.create, grant.create, grant.revoke
	// unit.create, holding.create, grant.create: the governing unit
	Unit string `json:"unit,omitempty"`
	// unit.create
	Name                string             `json:"name,omitempty"`
	ManagedScope        []sdkauthz.Segment `json:"managed_scope,omitempty"`
	GrantableOperations []string           `json:"grantable_operations,omitempty"`
	// holding.create
	Holder     string `json:"holder,omitempty"`
	SystemRole string `json:"system_role,omitempty"`
	// role.create
	SegmentsTemplate []sdkauthz.Segment `json:"segments_template,omitempty"`
	// grant.create: segments, or a role revision whose template is instantiated
	Grantee      string             `json:"grantee,omitempty"`
	RoleRevision string             `json:"role_revision,omitempty"`
	Segments     []sdkauthz.Segment `json:"segments,omitempty"`
	// holding.end, grant.revoke
	Target string `json:"target,omitempty"`
}

// result is what a change answers and what its key binds (security 09a, be.security.change_result).
type result struct {
	ChangeKey         string `json:"change_key"`
	Outcome           string `json:"outcome"` // applied, rejected
	Reason            string `json:"reason,omitempty"`
	Detail            string `json:"detail,omitempty"`
	Record            string `json:"record,omitempty"`
	SecurityRevisions int64  `json:"security_revision,omitempty"`
}

// errRejected carries a final rejection out of the effect point's transaction so its key is bound in a second one.
type errRejected struct{ result }

func (e *errRejected) Error() string { return e.Reason + ": " + e.Detail }

func reject(reason, detail string) error {
	return &errRejected{result{Outcome: "rejected", Reason: reason, Detail: detail}}
}

// apply runs one change at the effect point: one transaction under the deployment's guard; the change key, the
// requester's management, containment and the last admin are checked now, never from an earlier preview.
func (m *Module) apply(ctx context.Context, requester string, c change) (result, error) {
	if c.ChangeKey == "" {
		return result{}, errs.New(errs.ReasonRequestInvalid, "change_key is required")
	}
	body, _ := json.Marshal(c)
	var v any
	_ = json.Unmarshal(body, &v)
	contentDigest, err := canon.Digest("be.security.change_request", 1, numbersAsText(v))
	if err != nil {
		return result{}, errs.New(errs.ReasonRequestInvalid, "the change cannot be encoded: "+err.Error())
	}
	var res result
	err = m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT 1 FROM authz_state FOR UPDATE"); err != nil { // the guard: one change at a time
			return err
		}
		var bound, boundDigest []byte
		err := tx.QueryRow(ctx, "SELECT result, content_digest FROM authz_change WHERE requested_by = $1 AND change_key = $2",
			requester, c.ChangeKey).Scan(&bound, &boundDigest)
		switch {
		case err == nil && string(boundDigest) == contentDigest:
			return json.Unmarshal(bound, &res) // row 1: the bound result again
		case err == nil:
			return reject(errs.ReasonChangeKeyConflict, "this change key was used for another change") // row 2
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		res, err = m.effect(ctx, tx, requester, c)
		if err != nil {
			return err
		}
		res.ChangeKey = c.ChangeKey
		out, _ := json.Marshal(res)
		_, err = tx.Exec(ctx, `INSERT INTO authz_change (requested_by, change_key, content_digest, result) VALUES ($1, $2, $3, $4)`,
			requester, c.ChangeKey, contentDigest, out)
		return err
	})
	var rej *errRejected
	if errors.As(err, &rej) {
		res = rej.result
		res.ChangeKey = c.ChangeKey
		// a final rejection binds the key (security 08); a conflict and a definition still on its way do not (D77)
		if rej.Reason != errs.ReasonChangeKeyConflict && rej.Reason != errs.ReasonDefinitionPending {
			out, _ := json.Marshal(res)
			bindErr := m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
				_, err := tx.Exec(ctx, `INSERT INTO authz_change (requested_by, change_key, content_digest, result)
					VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`, requester, c.ChangeKey, contentDigest, out)
				return err
			})
			if bindErr != nil {
				return result{}, bindErr
			}
			_ = m.rt.Audit.Denial(ctx, audit.Record{Category: audit.SecurityDenial, Operation: OpChange, Outcome: audit.Denied,
				Reason: rej.Reason, Actor: requester, Changes: map[string]any{"action": c.Action}})
		}
		return res, nil
	}
	return res, err
}

// effect decides and writes one change inside the effect point's transaction.
func (m *Module) effect(ctx context.Context, tx db.Tx, requester string, c change) (result, error) {
	units, err := m.units(ctx, tx)
	if err != nil {
		return result{}, err
	}
	held, admin, err := holdingsOf(ctx, tx, requester)
	if err != nil {
		return result{}, err
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
	var typ string
	var rec any
	switch c.Action {
	case "unit.create":
		parent, ok := units[c.Unit]
		if !ok || !manages(c.Unit) {
			return result{}, reject(errs.ReasonPermissionDenied, "the requester does not manage the parent unit")
		}
		for _, op := range c.GrantableOperations {
			if !parent.Root && !slices.Contains(parent.GrantableOperations, op) {
				return result{}, reject(errs.ReasonContainmentNotProven, "operation "+op+" is not grantable in the parent unit")
			}
		}
		if err := m.within(ctx, tx, c.ManagedScope, parent, ""); err != nil {
			return result{}, err
		}
		typ, rec = "management_unit", unitBody{Name: c.Name, Parent: c.Unit, ManagedScope: c.ManagedScope,
			GrantableOperations: c.GrantableOperations}
	case "holding.create":
		if _, ok := units[c.Unit]; !ok || !manages(c.Unit) {
			return result{}, reject(errs.ReasonPermissionDenied, "the requester does not manage the unit")
		}
		if c.SystemRole != "" && (c.SystemRole != "authorization_admin" || !admin) {
			return result{}, reject(errs.ReasonPermissionDenied, "only an authorization admin names an authorization admin")
		}
		typ, rec = "management_holding", holdingBody{Unit: c.Unit, Holder: c.Holder, SystemRole: c.SystemRole}
	case "role.create":
		if !admin {
			return result{}, reject(errs.ReasonPermissionDenied, "roles are defined by authorization admins")
		}
		typ, rec = "role_revision", roleBody{Name: c.Name, SegmentsTemplate: c.SegmentsTemplate}
	case "grant.create":
		unit, ok := units[c.Unit]
		if !ok || !manages(c.Unit) {
			return result{}, reject(errs.ReasonPermissionDenied, "the requester does not manage the unit")
		}
		segs := c.Segments
		if c.RoleRevision != "" {
			if segs, err = roleTemplate(ctx, tx, c.RoleRevision); err != nil {
				return result{}, err
			}
		}
		if c.Grantee == "" || len(segs) == 0 {
			return result{}, reject(errs.ReasonRequestInvalid, "a grant needs a grantee and segments or a role revision")
		}
		if err := m.within(ctx, tx, segs, unit, c.Grantee); err != nil {
			return result{}, err
		}
		typ, rec = "grant", grantBody{Grantee: c.Grantee, RoleRevision: c.RoleRevision, Segments: segs,
			GovernanceUnit: c.Unit, IssuedBy: requester}
	case "grant.revoke", "holding.end":
		return m.end(ctx, tx, requester, c, units, manages)
	default:
		return result{}, reject(errs.ReasonRequestInvalid, "unknown action "+c.Action)
	}
	id := ids.New().String()
	body, err := json.Marshal(rec)
	if err != nil {
		return result{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO authz_record (id, record_type, state, body, requested_by) VALUES ($1, $2, 'active', $3, $4)`,
		id, typ, body, requester); err != nil {
		return result{}, err
	}
	return m.applied(ctx, tx, requester, c.Action, typ, id)
}

// end revokes a grant or ends a holding; the last authorization admin is never removed (security 08).
func (m *Module) end(ctx context.Context, tx db.Tx, requester string, c change, units map[string]unitBody,
	manages func(string) bool) (result, error) {
	var typ string
	var body json.RawMessage
	err := tx.QueryRow(ctx, "SELECT record_type, body FROM authz_record WHERE id = $1 AND state = 'active'", c.Target).Scan(&typ, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return result{}, reject(errs.ReasonChangeRevisionStale, "the target is not an active record")
	} else if err != nil {
		return result{}, err
	}
	var unit string
	switch {
	case c.Action == "grant.revoke" && typ == "grant":
		var g grantBody
		_ = json.Unmarshal(body, &g)
		unit = g.GovernanceUnit
	case c.Action == "holding.end" && typ == "management_holding":
		var h holdingBody
		_ = json.Unmarshal(body, &h)
		unit = h.Unit
		if h.SystemRole == "authorization_admin" {
			var others int
			if err := tx.QueryRow(ctx, `SELECT count(DISTINCT body->>'holder') FROM authz_record WHERE state = 'active'
				AND record_type = 'management_holding' AND body->>'system_role' = 'authorization_admin'
				AND body->>'holder' <> $1`, h.Holder).Scan(&others); err != nil {
				return result{}, err
			}
			if others == 0 {
				return result{}, reject(errs.ReasonLastAdminProtected, "this is the last authorization admin")
			}
		}
	default:
		return result{}, reject(errs.ReasonRequestInvalid, fmt.Sprintf("%s does not apply to a %s", c.Action, typ))
	}
	if !manages(unit) {
		return result{}, reject(errs.ReasonPermissionDenied, "the requester does not manage the record's unit")
	}
	reason := "revoked"
	if c.Action == "holding.end" {
		reason = "relinquished"
	}
	if _, err := tx.Exec(ctx, `UPDATE authz_record SET state = 'ended', end_reason = $2, revision = revision + 1,
		updated_at = now() WHERE id = $1`, c.Target, reason); err != nil {
		return result{}, err
	}
	return m.applied(ctx, tx, requester, c.Action, typ, c.Target)
}

// applied advances the security revision and writes the security change's audit record in the same transaction.
func (m *Module) applied(ctx context.Context, tx db.Tx, requester, action, typ, id string) (result, error) {
	if err := advance(ctx, tx); err != nil {
		return result{}, err
	}
	var rev int64
	if err := tx.QueryRow(ctx, "SELECT security_revision FROM authz_state").Scan(&rev); err != nil {
		return result{}, err
	}
	if _, err := m.rt.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: OpChange,
		Outcome: audit.Succeeded, Actor: requester, Target: map[string]any{"type": typ, "id": id},
		Changes: map[string]any{"action": action, "security_revision": fmt.Sprint(rev)}}); err != nil {
		return result{}, err
	}
	return result{Outcome: "applied", Record: id, SecurityRevisions: rev}, nil
}

// within proves every candidate segment is contained in one of the unit's limit segments for its operation (security
// 07; no split along a dimension in this step). A root unit contains every well-formed segment.
func (m *Module) within(ctx context.Context, tx db.Tx, segs []sdkauthz.Segment, unit unitBody, grantee string) error {
	for _, s := range segs {
		r, err := m.resourceFor(ctx, tx, s.ResourceType)
		if err != nil {
			return err
		}
		if r == nil {
			// its component is ready before its definitions are accepted (P8.24): retryable, the key stays free (D77)
			return reject(errs.ReasonDefinitionPending, "resource type "+s.ResourceType+" is not defined yet")
		}
		if err := s.Check(r); err != nil {
			return reject(errs.ReasonRequestInvalid, err.Error())
		}
		if unit.Root {
			continue
		}
		if !slices.Contains(unit.GrantableOperations, s.Operation) {
			return reject(errs.ReasonContainmentNotProven, "operation "+s.Operation+" is not grantable in the unit")
		}
		var last *notContained
		ok := slices.ContainsFunc(unit.ManagedScope, func(l sdkauthz.Segment) bool {
			last = contained(s, l, grantee)
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

func (m *Module) units(ctx context.Context, tx db.Tx) (map[string]unitBody, error) {
	recs, err := active(ctx, tx, "management_unit")
	if err != nil {
		return nil, err
	}
	out := map[string]unitBody{}
	for _, r := range recs {
		var u unitBody
		if err := json.Unmarshal(r.Body, &u); err != nil {
			return nil, err
		}
		out[r.ID] = u
	}
	return out, nil
}

// holdingsOf returns the units a principal holds and whether one holding makes it an authorization admin.
func holdingsOf(ctx context.Context, tx db.Tx, principal string) ([]string, bool, error) {
	recs, err := active(ctx, tx, "management_holding")
	if err != nil {
		return nil, false, err
	}
	var units []string
	admin := false
	for _, r := range recs {
		var h holdingBody
		if err := json.Unmarshal(r.Body, &h); err != nil {
			return nil, false, err
		}
		if h.Holder == principal {
			units = append(units, h.Unit)
			admin = admin || h.SystemRole == "authorization_admin"
		}
	}
	return units, admin, nil
}

func roleTemplate(ctx context.Context, tx db.Tx, id string) ([]sdkauthz.Segment, error) {
	var body json.RawMessage
	err := tx.QueryRow(ctx, "SELECT body FROM authz_record WHERE id = $1 AND record_type = 'role_revision' AND state = 'active'",
		id).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, reject(errs.ReasonRequestInvalid, "no such active role revision")
	} else if err != nil {
		return nil, err
	}
	var r roleBody
	return r.SegmentsTemplate, json.Unmarshal(body, &r)
}

// resourceFor finds a resource type among the current accepted definitions of every component.
func (m *Module) resourceFor(ctx context.Context, tx db.Tx, typ string) (*sdkauthz.Resource, error) {
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
	return resourceOf(body), nil
}

// numbersAsText makes a decoded request encodable canonically: numbers as text (no floating point), no nulls.
func numbersAsText(v any) any {
	switch x := v.(type) {
	case float64:
		return fmt.Sprint(x)
	case []any:
		out := x[:0]
		for _, e := range x {
			if e != nil {
				out = append(out, numbersAsText(e))
			}
		}
		return out
	case map[string]any:
		for k, e := range x {
			if e == nil {
				delete(x, k)
			} else {
				x[k] = numbersAsText(e)
			}
		}
	}
	return v
}
