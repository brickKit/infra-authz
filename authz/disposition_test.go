package authz

import (
	"testing"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/stretchr/testify/assert"
)

// TestASuspendedScopeMeetsUnlessProvablyDisjoint: security 08's evaluation of a disposition (whole segments that meet
// the suspended scope are left out); only security 07's table can prove two segments share nothing.
func TestASuspendedScopeMeetsUnlessProvablyDisjoint(t *testing.T) {
	seg := func(op string, atoms map[string]sdkauthz.Atom) sdkauthz.Segment {
		return sdkauthz.Segment{ResourceType: "demo.order", Operation: op, Atoms: atoms, Valid: sdkauthz.Window{From: "2026-01-01T00:00:00Z"}}
	}
	in := func(v ...string) map[string]sdkauthz.Atom {
		return map[string]sdkauthz.Atom{"region": {Kind: "in", Values: v}}
	}
	str := func(s string) *string { return &s }
	yes, no := true, false
	amount := func(lo, hi string, loC, hiC *bool, cur string) map[string]sdkauthz.Atom {
		return map[string]sdkauthz.Atom{"total": {Kind: "interval", Lo: str(lo), Hi: str(hi), LoClosed: loC, HiClosed: hiC, Currency: cur}}
	}
	tree := func(paths ...string) map[string]sdkauthz.Atom {
		items := []sdkauthz.TreeItem{}
		for _, p := range paths {
			items = append(items, sdkauthz.TreeItem{Path: p, Mode: "subtree"})
		}
		return map[string]sdkauthz.Atom{"org": {Kind: "tree", Items: items}}
	}
	cases := []struct {
		name     string
		a, scope sdkauthz.Segment
		disjoint bool
	}{
		{"another operation", seg("demo.order.read", in("east")), seg("demo.order.approve", in("east")), true},
		{"values in common", seg("demo.order.read", in("east", "west")), seg("demo.order.read", in("west")), false},
		{"no value in common", seg("demo.order.read", in("east")), seg("demo.order.read", in("west")), true},
		{"all meets everything", seg("demo.order.read", in("east")), seg("demo.order.read", map[string]sdkauthz.Atom{"region": {Kind: "all"}}), false},
		{"self within the values", seg("demo.order.read", map[string]sdkauthz.Atom{"region": {Kind: "self"}}), seg("demo.order.read", in("p1")), false},
		{"self outside the values", seg("demo.order.read", map[string]sdkauthz.Atom{"region": {Kind: "self"}}), seg("demo.order.read", in("p2")), true},
		{"a subtree under the other", seg("demo.order.read", tree("/a/b")), seg("demo.order.read", tree("/a")), false},
		{"separate subtrees", seg("demo.order.read", tree("/a")), seg("demo.order.read", tree("/b")), true},
		{"amounts overlapping", seg("demo.order.read", amount("0", "100", &yes, &yes, "EUR")), seg("demo.order.read", amount("50", "500", &yes, &yes, "EUR")), false},
		{"amounts touching at a closed end", seg("demo.order.read", amount("0", "100", &yes, &yes, "EUR")), seg("demo.order.read", amount("100", "500", &yes, &yes, "EUR")), false},
		{"amounts touching at an open end", seg("demo.order.read", amount("0", "100", &yes, &no, "EUR")), seg("demo.order.read", amount("100", "500", &yes, &yes, "EUR")), true},
		{"amounts apart", seg("demo.order.read", amount("0", "100", &yes, &yes, "EUR")), seg("demo.order.read", amount("200", "500", &yes, &yes, "EUR")), true},
		{"another currency", seg("demo.order.read", amount("0", "100", &yes, &yes, "EUR")), seg("demo.order.read", amount("0", "100", &yes, &yes, "USD")), true},
		{"a pair outside the table meets", seg("demo.order.read", in("east")), seg("demo.order.read", tree("/a")), false},
	}
	for _, c := range cases {
		assert.Equal(t, c.disjoint, disjoint(c.a, c.scope, "p1"), c.name)
	}
	later := seg("demo.order.read", in("east"))
	later.Valid = sdkauthz.Window{From: "2027-01-01T00:00:00Z"}
	earlier := seg("demo.order.read", in("east"))
	earlier.Valid = sdkauthz.Window{From: "2026-01-01T00:00:00Z", Until: "2026-06-01T00:00:00Z"}
	assert.True(t, disjoint(later, earlier, "p1"), "validities that do not overlap")

	ds := []disposition{{Segments: []sdkauthz.Segment{seg("demo.order.read", in("west"))}}}
	assert.False(t, suspended(ds, seg("demo.order.read", in("east")), "p1"), "outside the scope: given")
	assert.True(t, suspended(ds, seg("demo.order.read", in("east", "west")), "p1"), "meeting it: left out whole")
	assert.True(t, suspended([]disposition{{All: true}}, seg("demo.order.approve", in("east")), "p1"), "the person's every segment")
	assert.False(t, suspended(nil, seg("demo.order.read", in("east")), "p1"))
}
