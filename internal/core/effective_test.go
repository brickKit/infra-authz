package core

import (
	"testing"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The effective segments' intersection (security 07's atoms, security 08's "有效段的计算"), one case per rule.

func str(s string) *string { return &s }
func flag(b bool) *bool    { return &b }

func vals(v ...string) sdkauthz.Atom { return sdkauthz.Atom{Kind: "in", Values: v} }
func tree(items ...string) sdkauthz.Atom {
	a := sdkauthz.Atom{Kind: "tree"}
	for i := 0; i < len(items); i += 2 {
		a.Items = append(a.Items, sdkauthz.TreeItem{Path: items[i], Mode: items[i+1]})
	}
	return a
}
func interval(cur string, lo string, loClosed bool, hi string, hiClosed bool) sdkauthz.Atom {
	a := sdkauthz.Atom{Kind: "interval", Currency: cur}
	if lo != "" {
		a.Lo, a.LoClosed = str(lo), flag(loClosed)
	}
	if hi != "" {
		a.Hi, a.HiClosed = str(hi), flag(hiClosed)
	}
	return a
}

func TestAtomIntersection(t *testing.T) {
	all := sdkauthz.Atom{Kind: "all"}
	self := sdkauthz.Atom{Kind: "self"}
	for _, c := range []struct {
		name    string
		x, y    sdkauthz.Atom
		grantee string
		want    *sdkauthz.Atom // nil: empty
	}{
		{"all with anything is the other", all, vals("a"), "", &sdkauthz.Atom{Kind: "in", Values: []string{"a"}}},
		{"anything with all is itself", vals("a", "b"), all, "", &sdkauthz.Atom{Kind: "in", Values: []string{"a", "b"}}},
		{"value sets: the values in both", vals("a", "b", "c"), vals("b", "c", "d"), "", &sdkauthz.Atom{Kind: "in", Values: []string{"b", "c"}}},
		{"disjoint value sets: empty", vals("a"), vals("b"), "", nil},
		{"self within a set holding the grantee", self, vals("p1", "p2"), "p1", &self},
		{"self within a set without the grantee: empty", self, vals("p2"), "p1", nil},
		{"a set with self, the grantee in it", vals("p1"), self, "p1", &self},
		{"self, no grantee to instantiate it: empty", self, vals("p1"), "", nil},
		{"self with self", self, self, "p1", &self},
		{"a subtree within a subtree: the deeper", tree("/a/b", "subtree"), tree("/a", "subtree"), "", &sdkauthz.Atom{Kind: "tree", Items: []sdkauthz.TreeItem{{Path: "/a/b", Mode: "subtree"}}}},
		{"the other way round: the deeper", tree("/a", "subtree"), tree("/a/b", "subtree"), "", &sdkauthz.Atom{Kind: "tree", Items: []sdkauthz.TreeItem{{Path: "/a/b", Mode: "subtree"}}}},
		{"an exact node within a subtree", tree("/a/b", "exact"), tree("/a", "subtree"), "", &sdkauthz.Atom{Kind: "tree", Items: []sdkauthz.TreeItem{{Path: "/a/b", Mode: "exact"}}}},
		{"an exact node is no subtree: a subtree below it is outside", tree("/a/b", "subtree"), tree("/a", "exact"), "", nil},
		{"sibling subtrees: empty", tree("/a", "subtree"), tree("/b", "subtree"), "", nil},
		{"a prefix is not a parent", tree("/ab", "subtree"), tree("/a", "subtree"), "", nil},
		{"intervals: the tighter ends", interval("EUR", "0", true, "100", false), interval("EUR", "50", false, "200", true), "",
			&sdkauthz.Atom{Kind: "interval", Currency: "EUR", Lo: str("50"), LoClosed: flag(false), Hi: str("100"), HiClosed: flag(false)}},
		{"an unbounded end takes the other's", interval("EUR", "", false, "100", true), interval("EUR", "10", true, "", false), "",
			&sdkauthz.Atom{Kind: "interval", Currency: "EUR", Lo: str("10"), LoClosed: flag(true), Hi: str("100"), HiClosed: flag(true)}},
		{"disjoint intervals: empty", interval("EUR", "0", true, "10", true), interval("EUR", "20", true, "30", true), "", nil},
		{"touching closed ends: the one value", interval("EUR", "0", true, "10", true), interval("EUR", "10", true, "20", true), "",
			&sdkauthz.Atom{Kind: "interval", Currency: "EUR", Lo: str("10"), LoClosed: flag(true), Hi: str("10"), HiClosed: flag(true)}},
		{"the same lower end, one open: open", interval("EUR", "10", false, "20", true), interval("EUR", "10", true, "30", true), "",
			&sdkauthz.Atom{Kind: "interval", Currency: "EUR", Lo: str("10"), LoClosed: flag(false), Hi: str("20"), HiClosed: flag(true)}},
		{"touching, one end open: empty", interval("EUR", "0", true, "10", false), interval("EUR", "10", true, "20", true), "", nil},
		{"the same value, written differently, is equal", interval("EUR", "0", true, "10.0", true), interval("EUR", "10", true, "20", true), "",
			&sdkauthz.Atom{Kind: "interval", Currency: "EUR", Lo: str("10"), LoClosed: flag(true), Hi: str("10.0"), HiClosed: flag(true)}},
		{"another currency: empty", interval("EUR", "0", true, "", false), interval("USD", "0", true, "", false), "", nil},
		{"a pair outside the table: empty, never more", vals("a"), tree("/a", "subtree"), "", nil},
		// FX03: an explicit empty set, tree or interval leaves the segment out of the view, with all as well
		{"all with an explicit empty set: empty", all, vals(), "", nil},
		{"an explicit empty set with all: empty", vals(), all, "", nil},
		{"all with an empty tree: empty", all, tree(), "", nil},
		{"all with an empty interval: empty", all, interval("EUR", "10", true, "10", false), "", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := atomIntersect(c.x, c.y, c.grantee)
			if c.want == nil {
				assert.False(t, ok, "%+v", got)
				return
			}
			require.True(t, ok)
			assert.Equal(t, *c.want, got)
		})
	}
}

func oseg(op string, atom sdkauthz.Atom, fields []string, from, until string) sdkauthz.Segment {
	return sdkauthz.Segment{ResourceType: "demo.order", Operation: op, Atoms: map[string]sdkauthz.Atom{"region": atom},
		ReadFields: fields, Valid: sdkauthz.Window{From: from, Until: until}}
}

const (
	jan = "2026-01-01T00:00:00Z"
	feb = "2026-02-01T00:00:00Z"
	mar = "2026-03-01T00:00:00Z"
)

func TestSegmentIntersection(t *testing.T) {
	a := oseg("demo.order.read", vals("east", "west"), []string{"id", "total"}, jan, mar)
	a.Source = "grant-1"
	got, ok := intersect(a, oseg("demo.order.read", vals("east"), []string{"id"}, feb, ""), "")
	require.True(t, ok)
	assert.Equal(t, []string{"east"}, got.Atoms["region"].Values)
	assert.Equal(t, []string{"id"}, got.ReadFields, "the fields in both")
	assert.Equal(t, sdkauthz.Window{From: feb, Until: mar}, got.Valid, "the later start, the earlier end")
	assert.Equal(t, "grant-1", got.Source, "it stays the grant's segment")

	_, ok = intersect(a, oseg("demo.order.export", vals("east"), nil, jan, ""), "")
	assert.False(t, ok, "another operation")
	_, ok = intersect(a, oseg("demo.order.read", vals("north"), nil, jan, ""), "")
	assert.False(t, ok, "one dimension empty: the segment is empty")
	_, ok = intersect(a, oseg("demo.order.read", vals("east"), nil, mar, ""), "")
	assert.False(t, ok, "validities that do not overlap")
	b := oseg("demo.order.read", vals("east"), nil, jan, "")
	b.Atoms = map[string]sdkauthz.Atom{"warehouse": vals("w1")}
	_, ok = intersect(a, b, "")
	assert.False(t, ok, "not the same dimensions: malformed, nothing")
}

func TestUnitLimitsChainToTheRoot(t *testing.T) {
	ops := []string{"demo.order.read", "demo.order.export"}
	units := map[string]UnitBody{
		"root":  {Root: true},
		"wide":  {Parent: "root", ManagedScope: []sdkauthz.Segment{oseg("demo.order.read", vals("east", "north"), []string{"id"}, jan, "")}, GrantableOperations: ops[:1]},
		"sub":   {Parent: "wide", ManagedScope: []sdkauthz.Segment{oseg("demo.order.read", vals("east", "west"), []string{"id"}, jan, ""), oseg("demo.order.export", all(), nil, jan, "")}, GrantableOperations: ops},
		"stray": {Parent: "gone", ManagedScope: []sdkauthz.Segment{oseg("demo.order.read", vals("east"), nil, jan, "")}, GrantableOperations: ops},
	}
	l := NewLimits(units)
	assert.True(t, l.Of("root").All)
	sub := l.Of("sub")
	require.NotNil(t, sub)
	require.Len(t, sub.Segs, 1, "the export segment: its parent has no limit for it")
	assert.Equal(t, []string{"east"}, sub.Segs[0].Atoms["region"].Values, "{east, west} ∩ {east, north}")
	assert.Equal(t, []string{"demo.order.read"}, sub.Ops, "the operations its parent may grant too")
	assert.Nil(t, l.Of("stray"), "a parent not active: nothing is within it")
	cycle := NewLimits(map[string]UnitBody{"a": {Parent: "b", GrantableOperations: ops}, "b": {Parent: "a", GrantableOperations: ops}})
	assert.Nil(t, cycle.Of("a"), "a chain that never reaches the root: nothing is within it")
	assert.Nil(t, l.Of("nobody"))

	grant := []sdkauthz.Segment{oseg("demo.order.read", vals("east", "west"), []string{"id"}, jan, ""),
		oseg("demo.order.export", all(), nil, jan, "")}
	cut := sub.Cut(grant, "")
	require.Len(t, cut, 1, "an operation the unit may not grant gives nothing")
	assert.Equal(t, []string{"east"}, cut[0].Atoms["region"].Values)
	assert.Equal(t, grant, l.Of("root").Cut(grant, ""), "the root limits nothing")
	readOnly := NewLimits(map[string]UnitBody{"root": {Root: true}, "u": {Parent: "root", GrantableOperations: ops[:1],
		ManagedScope: []sdkauthz.Segment{oseg("demo.order.read", all(), []string{"id"}, jan, ""), oseg("demo.order.export", all(), nil, jan, "")}}})
	cut = readOnly.Of("u").Cut(grant, "")
	require.Len(t, cut, 1, "a scope segment for an operation the unit may not grant gives nothing")
	assert.Equal(t, "demo.order.read", cut[0].Operation)
	assert.Nil(t, l.Of("stray").Cut(grant, ""))
}

// A unit's limit for one grantee: self in a scope is that grantee, so it meets a parent's named set only for a
// person in it (security 07, "主体相对的原子"); without a grantee it meets nothing but another self.
func TestUnitLimitsForAGrantee(t *testing.T) {
	ops := []string{"demo.order.read"}
	self := sdkauthz.Atom{Kind: "self"}
	units := map[string]UnitBody{
		"root":   {Root: true},
		"named":  {Parent: "root", ManagedScope: []sdkauthz.Segment{oseg("demo.order.read", vals(grantee), []string{"id"}, jan, "")}, GrantableOperations: ops},
		"own":    {Parent: "named", ManagedScope: []sdkauthz.Segment{oseg("demo.order.read", self, []string{"id"}, jan, "")}, GrantableOperations: ops},
		"selves": {Parent: "root", ManagedScope: []sdkauthz.Segment{oseg("demo.order.read", self, []string{"id"}, jan, "")}, GrantableOperations: ops},
		"mine":   {Parent: "selves", ManagedScope: []sdkauthz.Segment{oseg("demo.order.read", self, []string{"id"}, jan, "")}, GrantableOperations: ops},
	}
	l := NewLimits(units)
	require.Len(t, l.OfFor("own", grantee).Segs, 1, "self ∩ {the grantee}")
	assert.Empty(t, l.OfFor("own", "someone-else").Segs, "self ∩ {the grantee} for another person: nothing")
	assert.Empty(t, l.Of("own").Segs, "no grantee: self does not meet a named set")
	require.Len(t, l.Of("mine").Segs, 1, "self ∩ self, whoever is granted")
	grant := []sdkauthz.Segment{oseg("demo.order.read", self, []string{"id"}, jan, "")}
	assert.Len(t, l.OfFor("own", grantee).Cut(grant, grantee), 1)
	assert.Empty(t, l.OfFor("own", "someone-else").Cut(grant, "someone-else"))
}

func all() sdkauthz.Atom { return sdkauthz.Atom{Kind: "all"} }

func TestRetiredPermissionKeys(t *testing.T) {
	r, err := ParseRegistry("kind\tkey\towner_component\tretired\npermission\tdemo.order.read\tdemo/orders\n" +
		"permission\tdemo.order.export\tdemo/orders\t2026-10-01\nresource_type\tdemo.order\tdemo/orders\n")
	require.NoError(t, err)
	assert.True(t, r.Usable("demo.order.read"))
	assert.False(t, r.Usable("demo.order.export"), "retired")
	assert.False(t, r.Usable("demo.order.cancel"), "not registered")
	assert.Equal(t, "demo/orders", r.Owner("permission", "demo.order.export"), "a retired key keeps its owner")
}
