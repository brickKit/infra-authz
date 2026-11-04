package authz

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/jackc/pgx/v5"
)

// target is the record a change is about, as the effect point reads it (locked).
type target struct {
	ID, Type, State, HoldReason, RequestedBy, Predecessor, CandidateDigest string
	StateRevision, Revision                                                int64
	Body                                                                   json.RawMessage
	EffectiveAt, ValidFrom, ValidUntil                                     *time.Time
	Future                                                                 bool // effective_at is after the database's now
	// CoolingOff: a protected widening the deployment owner confirmed, waiting out the cooling-off (security 08);
	// InCoolingOff, that cooling-off is not over by the database's now
	CoolingOff   *time.Time
	InCoolingOff bool
}

var uuidText = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func lockTarget(ctx context.Context, tx db.Tx, id string) (*target, error) {
	if !uuidText.MatchString(id) {
		return nil, nil
	}
	var t target
	var hold, pred, digest *string
	err := tx.QueryRow(ctx, `SELECT id::text, record_type, state, hold_reason, requested_by, predecessor::text,
			state_revision, revision, body, effective_at, valid_from, valid_until, coalesce(effective_at > now(), false),
			candidate_digest, cooling_off_until, coalesce(cooling_off_until > now(), false)
		FROM authz_record WHERE id = $1 FOR UPDATE`, id).Scan(&t.ID, &t.Type, &t.State, &hold, &t.RequestedBy, &pred,
		&t.StateRevision, &t.Revision, &t.Body, &t.EffectiveAt, &t.ValidFrom, &t.ValidUntil, &t.Future, &digest,
		&t.CoolingOff, &t.InCoolingOff)
	if digest != nil {
		t.CandidateDigest = *digest
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if hold != nil {
		t.HoldReason = *hold
	}
	if pred != nil {
		t.Predecessor = *pred
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
		if json.Unmarshal(raw, &next) != nil || next.Parent != cur.Parent || next.Name != cur.Name || cur.Root ||
			!coversAll(cur.ManagedScope, next.ManagedScope) || unitShape(next) != "" ||
			cur.MaxSubdelegationDepth != nil && *next.MaxSubdelegationDepth > *cur.MaxSubdelegationDepth {
			return nil, false
		}
		for _, a := range next.ManagementActions { // fewer actions, a smaller depth: a narrowing too (A131)
			if !slices.Contains(cur.ManagementActions, a) {
				return nil, false
			}
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

// renames reads a neutral change's candidate: the same record with another name, nothing else changed. Only units
// and role revisions have one.
func renames(t *target, raw json.RawMessage) (any, bool) {
	var cur, next map[string]any
	if json.Unmarshal(t.Body, &cur) != nil || json.Unmarshal(raw, &next) != nil {
		return nil, false
	}
	delete(next, "record_type")
	name, _ := next["name"].(string)
	if (t.Type != "management_unit" && t.Type != "role_revision") || name == "" || name == cur["name"] {
		return nil, false
	}
	cur["name"] = name
	a, _ := json.Marshal(cur)
	b, _ := json.Marshal(next)
	if string(a) != string(b) { // encoding/json sorts map keys: equal text is equal content
		return nil, false
	}
	return json.RawMessage(a), true
}

// affectsAdmins: a tightening of t touches an authorization admin holding's availability (security 03; security 08's
// dependency index): t is such a holding, or the management unit one sits in, or a unit above it. A requester judged
// by the last applied facts does not act alone on these (row 12), and their confirmers are proven now (row 22).
func affectsAdmins(ctx context.Context, tx db.Tx, units map[string]unitBody, t *target) (bool, error) {
	switch t.Type {
	case "management_holding":
		var h holdingBody
		_ = json.Unmarshal(t.Body, &h)
		return h.SystemRole == "authorization_admin", nil
	case "management_unit":
		recs, err := active(ctx, tx, "management_holding")
		if err != nil {
			return false, err
		}
		for _, r := range recs {
			var h holdingBody
			if err := json.Unmarshal(r.Body, &h); err != nil {
				return false, err
			}
			if h.SystemRole != "authorization_admin" {
				continue
			}
			// up the parent chain from the holding's unit; a chain longer than the units is broken: count it as touched
			u := h.Unit
			for range len(units) + 1 {
				if sameUnit(units, u, t.ID) {
					return true, nil
				}
				if u = units[u].Parent; u == "" {
					break
				}
			}
			if u != "" {
				return true, nil
			}
		}
	}
	return false, nil
}
