package member

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
type unitBody struct {
	Name                string             `json:"name"`
	Parent              string             `json:"parent,omitempty"`
	Root                bool               `json:"root,omitempty"` // the install claim's unit: every declared resource and operation
	ManagedScope        []sdkauthz.Segment `json:"managed_scope"`
	GrantableOperations []string           `json:"grantable_operations"`
}

type holdingBody struct {
	Unit       string `json:"unit"`
	Holder     string `json:"holder"`                // the platform principal
	SystemRole string `json:"system_role,omitempty"` // authorization_admin
}

type roleBody struct {
	Name             string             `json:"name"`
	SegmentsTemplate []sdkauthz.Segment `json:"segments_template"`
}

type grantBody struct {
	Grantee        string             `json:"grantee"`
	RoleRevision   string             `json:"role_revision,omitempty"`
	Segments       []sdkauthz.Segment `json:"segments"`
	GovernanceUnit string             `json:"governance_unit"`
	IssuedBy       string             `json:"issued_by"`
}

// record is one active security record as read from the table.
type record struct {
	ID, Type string
	Revision int64
	Body     json.RawMessage
}

// active reads the active records of some types.
func active(ctx context.Context, tx db.Tx, types ...string) ([]record, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, record_type, revision, body FROM authz_record
		WHERE state = 'active' AND record_type = ANY($1) ORDER BY created_at, id`, types)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []record
	for rows.Next() {
		var r record
		if err := rows.Scan(&r.ID, &r.Type, &r.Revision, &r.Body); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// resourceOf turns an accepted resource definition back into the SDK's declaration, for the segment checks.
func resourceOf(body map[string]any) *sdkauthz.Resource {
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
type notContained struct{ dimension, why string }

func (n *notContained) Error() string { return n.dimension + ": " + n.why }

// contained is security 07's per-dimension containment of one candidate segment in one limit segment; grantee
// instantiates a candidate's self. nil means contained.
func contained(c, l sdkauthz.Segment, grantee string) *notContained {
	if c.ResourceType != l.ResourceType || c.Operation != l.Operation {
		return &notContained{"operation", "another resource type or operation"}
	}
	for dim, ca := range c.Atoms {
		la, ok := l.Atoms[dim]
		if !ok {
			return &notContained{dim, "the limit has no atom for it"}
		}
		if n := atomContained(ca, la, grantee); n != "" {
			return &notContained{dim, n}
		}
	}
	for _, f := range c.ReadFields {
		if !slices.Contains(l.ReadFields, f) {
			return &notContained{"read_fields", "field " + f + " is beyond the limit"}
		}
	}
	for _, f := range c.WriteFields {
		if !slices.Contains(l.WriteFields, f) {
			return &notContained{"write_fields", "field " + f + " is beyond the limit"}
		}
	}
	if !windowInside(c.Valid, l.Valid) {
		return &notContained{"valid", "the validity is beyond the limit's"}
	}
	return nil
}

// atomContained answers "" when the candidate atom is within the limit atom, else why not ("unprovable" when the
// pair is outside the rule table: never passed by dropping the hard part).
func atomContained(c, l sdkauthz.Atom, grantee string) string {
	if l.Kind == "all" {
		return ""
	}
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
	case c.Kind == "self" && l.Kind == "in":
		if slices.Contains(l.Values, grantee) {
			return ""
		}
		return "the grantee is beyond the limit"
	case c.Kind == "tree" && l.Kind == "tree":
		for _, it := range c.Items {
			if !slices.ContainsFunc(l.Items, func(li sdkauthz.TreeItem) bool { return covers(li, it) }) {
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

// covers: a subtree covers any node or subtree below it, an exact node only itself (security 07).
func covers(limit, c sdkauthz.TreeItem) bool {
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
	cmp, ok := decimalCompare(*c, *l)
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

// decimalCompare compares two decimal texts exactly.
func decimalCompare(a, b string) (int, bool) {
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
