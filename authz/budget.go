package authz

import (
	"context"
	"encoding/json"
	"fmt"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/db"
)

// Budgets (security 07, "预算"): checked when a grant is made, renewed, or restored, so an excess shows in the
// administration rather than as a query that cannot complete. Start values, to be calibrated by the representative
// deployment's experiments. A widening over a budget is rejected (row 19), a restore over one stays held (row 26).
const (
	budgetGrantSegments   = 8    // segments one grant's "or" expands to, on one resource type and operation
	budgetInValues        = 1000 // values in one in atom
	budgetTreeItems       = 64   // items in one org-tree atom
	budgetSubjectSegments = 64   // a subject's normalized segments on one resource type and operation
	overBudget            = "over budget: "
)

// grantBudget is why one grant's segments are over a budget, "" within. A grant's segments are the expansion of its
// "or" (security 07's normalization, step 4): counted on each resource type and operation, since segments of other
// operations are not one expansion (a role of twenty operations is twenty segments and expands nothing).
func grantBudget(segs []sdkauthz.Segment) string {
	per := map[string]int{}
	for _, s := range segs {
		op := s.ResourceType + " " + s.Operation
		if per[op]++; per[op] > budgetGrantSegments {
			return fmt.Sprintf(overBudget+"more than %d segments in one grant on %s %s", budgetGrantSegments, s.ResourceType, s.Operation)
		}
	}
	for _, s := range segs {
		for dim, a := range s.Atoms {
			switch {
			case a.Kind == "in" && len(a.Values) > budgetInValues:
				return fmt.Sprintf(overBudget+"%d values on %s (at most %d): use an org tree or another dimension",
					len(a.Values), dim, budgetInValues)
			case a.Kind == "tree" && len(a.Items) > budgetTreeItems:
				return fmt.Sprintf(overBudget+"%d tree items on %s (at most %d): use a subtree above them or another dimension",
					len(a.Items), dim, budgetTreeItems)
			}
		}
	}
	return ""
}

// subjectBudget is why a subject's segments on one resource type and operation would be over the budget with the
// candidate's added to what they hold, "" within. Segments are counted as normalized: the same scope, validity and
// binding merge (security 07's step 5, fields joined), whichever grant they come from.
func subjectBudget(held, cand []sdkauthz.Segment) string {
	scopes := map[string]map[string]bool{} // resource type and operation → normalized scopes
	for _, s := range append(append([]sdkauthz.Segment{}, held...), cand...) {
		op := s.ResourceType + " " + s.Operation
		key, _ := json.Marshal(struct {
			Atoms   map[string]sdkauthz.Atom
			Valid   sdkauthz.Window
			Binding string
		}{s.Atoms, s.Valid, s.Binding})
		if scopes[op] == nil {
			scopes[op] = map[string]bool{}
		}
		scopes[op][string(key)] = true
		if n := len(scopes[op]); n > budgetSubjectSegments {
			return fmt.Sprintf(overBudget+"more than %d segments for one person on %s %s", budgetSubjectSegments,
				s.ResourceType, s.Operation)
		}
	}
	return ""
}

// heldSegments are the segments of the grantee's grants in effect or waiting to take effect, other than those
// named (the record being restored or activated, the predecessor a renewal supersedes).
func heldSegments(ctx context.Context, tx db.Tx, grantee string, other ...string) ([]sdkauthz.Segment, error) {
	if other == nil {
		other = []string{}
	}
	rows, err := tx.Query(ctx, `SELECT body FROM authz_record WHERE record_type = 'grant' AND state IN ('active', 'scheduled')
		AND body->>'grantee' = $1 AND NOT id::text = ANY($2)`, grantee, other)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sdkauthz.Segment
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var b grantBody
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, err
		}
		out = append(out, b.Segments...)
	}
	return out, rows.Err()
}

// grantOverBudget is why a grant (the candidate, a saved one coming due, one being restored or released) is over a
// budget, "" within: its own budgets, then its grantee's with it; exclude are the records it does not add to.
func grantOverBudget(ctx context.Context, tx db.Tx, b grantBody, exclude ...string) (string, error) {
	if why := grantBudget(b.Segments); why != "" {
		return why, nil
	}
	held, err := heldSegments(ctx, tx, b.Grantee, exclude...)
	if err != nil {
		return "", err
	}
	return subjectBudget(held, b.Segments), nil
}

// budgetOf sets f.OverBudget and why for a grant at the effect point (rows 19, 26).
func (m *Module) budgetOf(ctx context.Context, tx db.Tx, b grantBody, f *facts, p *plan, exclude ...string) error {
	why, err := grantOverBudget(ctx, tx, b, exclude...)
	f.OverBudget, p.whyOver = why != "", why
	return err
}
