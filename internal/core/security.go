package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/db"
)

// The record-specific fields this step keeps (security 09a, "各类型的专有字段"; a subset).
type UnitBody struct {
	Name                string             `json:"name"`
	Parent              string             `json:"parent,omitempty"`
	Root                bool               `json:"root,omitempty"` // the install claim's unit: every declared resource and operation
	ManagedScope        []sdkauthz.Segment `json:"managed_scope"`
	GrantableOperations []string           `json:"grantable_operations"`
	// what its holders may do in it and below, and how many levels may still be made below it (09a, delegate.go)
	ManagementActions     []string `json:"management_actions"`
	MaxSubdelegationDepth *int     `json:"max_subdelegation_depth"`

	ID string `json:"-"` // the unit's current record: itself, or the active successor of a superseded one (units)
}

type HoldingBody struct {
	Unit       string `json:"unit"`
	Holder     string `json:"holder"`                // the platform principal
	SystemRole string `json:"system_role,omitempty"` // authorization_admin
	// BackfillPending is 09a's confirmation_backfill_pending: an admin account re-enabled without a valid
	// confirmation; the holding is not available until a protected reconfirmation (T9d)
	BackfillPending bool `json:"confirmation_backfill_pending,omitempty"`
	// Appointment binds the holding to an appointment of the employee member (security 04): it counts while the
	// appointment is active and the holder linked to its employee
	Appointment string `json:"appointment,omitempty"`
}

type RoleBody struct {
	Name             string             `json:"name"`
	SegmentsTemplate []sdkauthz.Segment `json:"segments_template"`
}

type GrantBody struct {
	Grantee        string             `json:"grantee"`
	RoleRevision   string             `json:"role_revision,omitempty"`
	Segments       []sdkauthz.Segment `json:"segments"`
	GovernanceUnit string             `json:"governance_unit"`
	IssuedBy       string             `json:"issued_by"`
	// Appointment binds the grant to an appointment of the employee member (security 04, D30): it gives access while
	// the appointment is active and the grantee linked to its employee; its end ends the grant
	Appointment string `json:"appointment,omitempty"`
}

// Record is one active security record as read from the table.
type Record struct {
	ID, Type string
	Revision int64
	Body     json.RawMessage
}

// Active (past valid_until a record gives no access at once: the closure job ends it later, security 08) reads the active records of some types.
func Active(ctx context.Context, tx db.Tx, types ...string) ([]Record, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, record_type, revision, body FROM authz_record
		WHERE state = 'active' AND record_type = ANY($1) AND (valid_from IS NULL OR valid_from <= now())
			AND (valid_until IS NULL OR valid_until > now()) ORDER BY created_at, id`, types)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.ID, &r.Type, &r.Revision, &r.Body); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ResourceOf turns an accepted resource definition back into the SDK's declaration, for the segment checks.
func ResourceOf(body map[string]any) *sdkauthz.Resource {
	r := &sdkauthz.Resource{Dimensions: map[string]sdkauthz.Dimension{}, Fields: map[string]sdkauthz.Field{}}
	r.Type, _ = body["type"].(string)
	r.ViewOperation, _ = body["view_operation"].(string)
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	if dims, ok := body["dimensions"].(map[string]any); ok {
		for name, d := range dims {
			dm, _ := d.(map[string]any)
			r.Dimensions[name] = sdkauthz.Dimension{Kind: str(dm, "kind"), Column: str(dm, "column"),
				PrincipalRole: str(dm, "principal_role"), CurrencyColumn: str(dm, "currency_column")}
		}
	}
	if fields, ok := body["fields"].(map[string]any); ok {
		for name, f := range fields {
			fm, _ := f.(map[string]any)
			r.Fields[name] = sdkauthz.Field{Class: str(fm, "class"), ReadKey: str(fm, "read_key"), WriteKey: str(fm, "write_key")}
		}
	}
	return r
}

// Why a candidate is not within a limit (security 07, "见证与结果").
type NotContained struct{ dimension, why string }

func (n *NotContained) Error() string { return n.dimension + ": " + n.why }

// Contained is security 07's per-dimension containment of one candidate segment in one limit segment; grantee
// instantiates a candidate's self. nil means contained.
func Contained(c, l sdkauthz.Segment, grantee string) *NotContained {
	if c.ResourceType != l.ResourceType || c.Operation != l.Operation {
		return &NotContained{"operation", "another resource type or operation"}
	}
	for dim, ca := range c.Atoms {
		la, ok := l.Atoms[dim]
		if !ok {
			return &NotContained{dim, "the limit has no atom for it"}
		}
		if n := atomContained(ca, la, grantee); n != "" {
			return &NotContained{dim, n}
		}
	}
	for _, f := range c.ReadFields {
		if !slices.Contains(l.ReadFields, f) {
			return &NotContained{"read_fields", "field " + f + " is beyond the limit"}
		}
	}
	for _, f := range c.WriteFields {
		if !slices.Contains(l.WriteFields, f) {
			return &NotContained{"write_fields", "field " + f + " is beyond the limit"}
		}
	}
	if !windowInside(c.Valid, l.Valid) {
		return &NotContained{"valid", "the validity is beyond the limit's"}
	}
	return nil
}

// atomContained answers "" when the candidate atom is within the limit atom, else why not ("unprovable" when the
// pair is outside the rule table: never passed by dropping the hard part). Both sides' self is the grantee
// (security 07: instantiated before any comparison); with no grantee yet (a unit's scope within its parent's) self
// stands for whoever is granted later, so only another self contains it.
func atomContained(c, l sdkauthz.Atom, grantee string) string {
	if l.Kind == "all" {
		return ""
	}
	if c.Kind == "self" && l.Kind == "self" {
		return ""
	}
	c, l = instantiate(c, grantee), instantiate(l, grantee)
	switch {
	case c.Kind == "all":
		return "the candidate is all, the limit is not"
	case c.Kind == "in" && l.Kind == "in":
		for _, v := range c.Values {
			if !slices.Contains(l.Values, v) {
				return "value " + v + " is beyond the limit"
			}
		}
		return ""
	case c.Kind == "self" || l.Kind == "self":
		return "unprovable (self with no grantee to stand for)"
	case c.Kind == "tree" && l.Kind == "tree":
		for _, it := range c.Items {
			if !slices.ContainsFunc(l.Items, func(li sdkauthz.TreeItem) bool { return Covers(li, it) }) {
				return "subtree " + it.Path + " is beyond the limit"
			}
		}
		return ""
	case c.Kind == "interval" && l.Kind == "interval":
		if c.Currency != l.Currency {
			return "another currency"
		}
		if !boundInside(c.Lo, c.LoClosed, l.Lo, l.LoClosed, -1) || !boundInside(c.Hi, c.HiClosed, l.Hi, l.HiClosed, 1) {
			return "the interval is beyond the limit"
		}
		return ""
	}
	return fmt.Sprintf("unprovable (%s within %s)", c.Kind, l.Kind)
}

// instantiate is a subject-relative atom for the grantee: self is the set of the grantee alone (security 07).
func instantiate(a sdkauthz.Atom, grantee string) sdkauthz.Atom {
	if a.Kind == "self" && grantee != "" {
		return sdkauthz.Atom{Kind: "in", Values: []string{grantee}}
	}
	return a
}

// Covers: a subtree covers any node or subtree below it, an exact node only itself (security 07).
func Covers(limit, c sdkauthz.TreeItem) bool {
	if limit.Mode == "exact" {
		return c.Mode == "exact" && c.Path == limit.Path
	}
	return c.Path == limit.Path || len(c.Path) > len(limit.Path) && c.Path[:len(limit.Path)+1] == limit.Path+"/"
}

// boundInside compares one end of two intervals; side -1 is the lower end, 1 the upper. An unbounded limit end
// contains everything; an unbounded candidate end only an unbounded limit end.
func boundInside(c *string, cClosed *bool, l *string, lClosed *bool, side int) bool {
	if l == nil {
		return true
	}
	if c == nil {
		return false
	}
	cmp, ok := DecimalCompare(*c, *l)
	if !ok {
		return false
	}
	switch {
	case cmp*side < 0:
		return true
	case cmp == 0:
		return *lClosed || !*cClosed // an open limit end does not contain a closed candidate end at the same value
	}
	return false
}

// DecimalCompare compares two decimal texts exactly.
func DecimalCompare(a, b string) (int, bool) {
	x, ok1 := new(big.Rat).SetString(a)
	y, ok2 := new(big.Rat).SetString(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	return x.Cmp(y), true
}

func windowInside(c, l sdkauthz.Window) bool {
	parse := func(s string) (time.Time, bool) {
		t, err := time.Parse(time.RFC3339Nano, s)
		return t, err == nil
	}
	cf, ok1 := parse(c.From)
	lf, ok2 := parse(l.From)
	if !ok1 || !ok2 || cf.Before(lf) {
		return false
	}
	if l.Until == "" {
		return true
	}
	if c.Until == "" {
		return false
	}
	cu, ok1 := parse(c.Until)
	lu, ok2 := parse(l.Until)
	return ok1 && ok2 && !cu.After(lu)
}
