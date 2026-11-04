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
	ID, Type, State, HoldReason, RequestedBy, Predecessor string
	StateRevision, Revision                               int64
	Body                                                  json.RawMessage
	EffectiveAt, ValidFrom, ValidUntil                    *time.Time
	Future                                                bool // effective_at is after the database's now
}

var uuidText = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func lockTarget(ctx context.Context, tx db.Tx, id string) (*target, error) {
	if !uuidText.MatchString(id) {
		return nil, nil
	}
	var t target
	var hold, pred *string
	err := tx.QueryRow(ctx, `SELECT id::text, record_type, state, hold_reason, requested_by, predecessor::text,
			state_revision, revision, body, effective_at, valid_from, valid_until, coalesce(effective_at > now(), false)
		FROM authz_record WHERE id = $1 FOR UPDATE`, id).Scan(&t.ID, &t.Type, &t.State, &hold, &t.RequestedBy, &pred,
		&t.StateRevision, &t.Revision, &t.Body, &t.EffectiveAt, &t.ValidFrom, &t.ValidUntil, &t.Future)
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
