package effectpoint

import (
	"fmt"
	"strings"
	"testing"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/stretchr/testify/assert"
)

// TestGrantBudgets: security 07's budgets checked when a grant is made, each at its start value and one beyond.
func TestGrantBudgets(t *testing.T) {
	values := func(n int) sdkauthz.Atom {
		v := make([]string, n)
		for i := range v {
			v[i] = fmt.Sprintf("w%d", i)
		}
		return vals(v...)
	}
	items := func(n int) sdkauthz.Atom {
		a := sdkauthz.Atom{Kind: "tree"}
		for i := 0; i < n; i++ {
			a.Items = append(a.Items, sdkauthz.TreeItem{Path: fmt.Sprintf("le1/d%d", i), Mode: "subtree"})
		}
		return a
	}
	segs := func(n int) []sdkauthz.Segment {
		out := make([]sdkauthz.Segment, n)
		for i := range out {
			out[i] = oseg("demo.order.read", vals(fmt.Sprintf("w%d", i)), []string{"id"}, jan, "")
		}
		return out
	}
	ops := func(n int) []sdkauthz.Segment {
		out := make([]sdkauthz.Segment, n)
		for i := range out {
			out[i] = oseg(fmt.Sprintf("demo.order.op%d", i), vals("w0"), []string{"id"}, jan, "")
		}
		return out
	}
	one := func(a sdkauthz.Atom) []sdkauthz.Segment {
		return []sdkauthz.Segment{oseg("demo.order.read", a, []string{"id"}, jan, "")}
	}
	cases := []struct {
		name string
		segs []sdkauthz.Segment
		over string // a part of why, "" within
	}{
		{"8 segments", segs(BudgetGrantSegments), ""},
		{"9 segments", segs(BudgetGrantSegments + 1), "segments"},
		// the expansion of a grant's "or" (security 07's normalization, step 4): counted on one resource type and
		// operation; a grant of many operations, one segment each, expands nothing
		{"20 operations, one segment each", ops(20), ""},
		{"1,000 values", one(values(BudgetInValues)), ""},
		{"1,001 values", one(values(BudgetInValues + 1)), "values"},
		{"64 tree items", one(items(BudgetTreeItems)), ""},
		{"65 tree items", one(items(BudgetTreeItems + 1)), "tree items"},
	}
	for _, c := range cases {
		why := grantBudget(c.segs)
		if c.over == "" {
			assert.Empty(t, why, c.name)
		} else {
			assert.Contains(t, why, c.over, c.name)
			assert.True(t, strings.HasPrefix(why, "over budget"), "%s: %s", c.name, why)
		}
	}
}

// TestSubjectBudget: one subject's segments on one resource type and operation, counted as normalized (the same
// scope, validity and binding merge, security 07 step 5) across what they hold and the candidate.
func TestSubjectBudget(t *testing.T) {
	segs := func(op string, from, n int) []sdkauthz.Segment {
		out := make([]sdkauthz.Segment, n)
		for i := range out {
			out[i] = oseg(op, vals(fmt.Sprintf("w%d", from+i)), []string{"id"}, jan, "")
		}
		return out
	}
	held := segs("demo.order.read", 0, BudgetSubjectSegments-1)
	assert.Empty(t, subjectBudget(held, segs("demo.order.read", 1000, 1)), "64 in all")
	assert.Contains(t, subjectBudget(held, segs("demo.order.read", 1000, 2)), "over budget", "65 in all")
	assert.Empty(t, subjectBudget(held, segs("demo.order.export", 1000, 2)), "another operation counts on its own")
	same := []sdkauthz.Segment{oseg("demo.order.read", vals("w0"), []string{"total"}, jan, ""), oseg("demo.order.read", vals("w1"), nil, jan, "")}
	assert.Empty(t, subjectBudget(held, append(same, segs("demo.order.read", 1000, 1)...)),
		"segments with a held one's scope merge with it: 64 in all")
	other := oseg("demo.order.read", vals("w0"), []string{"id"}, "2026-02-01T00:00:00Z", "")
	assert.Contains(t, subjectBudget(held, append(segs("demo.order.read", 1000, 1), other)), "over budget",
		"another validity does not merge")
}
