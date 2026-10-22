package authz

import (
	"testing"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/mergesafety"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const grantee = "0190f3a1-0000-7000-8000-0000000000b2"

func ptr[T any](v T) *T { return &v }

func seg(atoms map[string]sdkauthz.Atom, read ...string) sdkauthz.Segment {
	return sdkauthz.Segment{ResourceType: "demo.order", Operation: "demo.order.read", Atoms: atoms, ReadFields: read,
		Valid: sdkauthz.Window{From: "2026-01-01T00:00:00.000000Z"}}
}

// TestContainmentRules: security 07's per-dimension rules, one case per row and the refusals.
func TestContainmentRules(t *testing.T) {
	all := sdkauthz.Atom{Kind: "all"}
	in := func(v ...string) sdkauthz.Atom { return sdkauthz.Atom{Kind: "in", Values: v} }
	tree := func(items ...sdkauthz.TreeItem) sdkauthz.Atom { return sdkauthz.Atom{Kind: "tree", Items: items} }
	sub := func(p string) sdkauthz.TreeItem { return sdkauthz.TreeItem{Path: p, Mode: "subtree"} }
	exact := func(p string) sdkauthz.TreeItem { return sdkauthz.TreeItem{Path: p, Mode: "exact"} }
	interval := func(lo, hi string, loC, hiC bool) sdkauthz.Atom {
		return sdkauthz.Atom{Kind: "interval", Currency: "CNY", Lo: ptr(lo), LoClosed: ptr(loC), Hi: ptr(hi), HiClosed: ptr(hiC)}
	}
	cases := []struct {
		name      string
		cand, lim sdkauthz.Atom
		contained bool
	}{
		{"anything within all", in("w1"), all, true},
		{"all within all", all, all, true},
		{"all not within a set", all, in("w1", "w2"), false},
		{"subset", in("w1"), in("w1", "w2"), true},
		{"beyond the set", in("w1", "w3"), in("w1", "w2"), false},
		{"self within a set holding the grantee", sdkauthz.Atom{Kind: "self"}, in(grantee), true},
		{"self within a set without the grantee", sdkauthz.Atom{Kind: "self"}, in("someone-else"), false},
		{"self within self is unprovable", sdkauthz.Atom{Kind: "self"}, sdkauthz.Atom{Kind: "self"}, false},
		{"node under a subtree", tree(exact("le1/d1/d2")), tree(sub("le1/d1")), true},
		{"subtree under a subtree", tree(sub("le1/d1/d2")), tree(sub("le1/d1")), true},
		{"a sibling with a shared prefix", tree(sub("le1/d10")), tree(sub("le1/d1")), false},
		{"exact never covers a subtree", tree(sub("le1/d1")), tree(exact("le1/d1")), false},
		{"exact covers itself", tree(exact("le1/d1")), tree(exact("le1/d1")), true},
		{"interval inside", interval("100", "500", true, false), interval("0", "1000", true, true), true},
		{"interval beyond", interval("100", "1500", true, false), interval("0", "1000", true, true), false},
		{"closed end in an open limit end", interval("0", "1000", true, true), interval("0", "1000", false, true), false},
		{"another currency", sdkauthz.Atom{Kind: "interval", Currency: "USD", Lo: ptr("1"), LoClosed: ptr(true)},
			interval("0", "1000", true, true), false},
		{"in within a tree is unprovable", in("w1"), tree(sub("le1")), false},
	}
	for _, c := range cases {
		got := contained(seg(map[string]sdkauthz.Atom{"d": c.cand}), seg(map[string]sdkauthz.Atom{"d": c.lim}), grantee)
		assert.Equal(t, c.contained, got == nil, "%s: %v", c.name, got)
	}
	// fields, operation and validity
	lim := seg(map[string]sdkauthz.Atom{}, "id", "total")
	assert.Nil(t, contained(seg(map[string]sdkauthz.Atom{}, "id"), lim, grantee))
	assert.NotNil(t, contained(seg(map[string]sdkauthz.Atom{}, "id", "cost"), lim, grantee), "a field beyond the limit")
	other := seg(map[string]sdkauthz.Atom{}, "id")
	other.Operation = "demo.order.approve"
	assert.NotNil(t, contained(other, lim, grantee), "another operation")
	early := seg(map[string]sdkauthz.Atom{}, "id")
	early.Valid.From = "2025-01-01T00:00:00.000000Z"
	assert.NotNil(t, contained(early, lim, grantee), "a validity starting before the limit's")
	open := seg(map[string]sdkauthz.Atom{}, "id")
	bounded := lim
	bounded.Valid.Until = "2027-01-01T00:00:00.000000Z"
	assert.NotNil(t, contained(open, bounded, grantee), "an open end beyond a bounded limit")
}

func TestRegistry(t *testing.T) {
	r, err := parseRegistry("kind\tkey\towner_component\n# a comment\nresource_type\tdemo.order\tdemo/order\npermission\tdemo.order.read\tdemo/order\n")
	require.NoError(t, err)
	assert.Equal(t, "demo/order", r.owner("resource_type", "demo.order"))
	assert.Equal(t, "demo/order", r.owner("permission", "demo.order.read"))
	assert.Empty(t, r.owner("permission", "demo.order"), "kinds are separate")
	_, err = parseRegistry("table\tx\ty\n")
	assert.Error(t, err)
}

func TestCrossCheck(t *testing.T) {
	res := accepted{recordType: "be.security.resource_definition", key: "demo.order", digest: "r",
		body: map[string]any{"view_operation": "demo.order.read"}}
	read := accepted{recordType: "be.security.operation_definition", key: "demo.order.read", digest: "o1",
		body: map[string]any{"resource_type": "demo.order"}}
	stray := accepted{recordType: "be.security.operation_definition", key: "demo.invoice.read", digest: "o2",
		body: map[string]any{"resource_type": "demo.invoice"}}
	assert.Empty(t, crossCheck([]accepted{res, read}))
	bad := crossCheck([]accepted{res, read, stray})
	require.Len(t, bad, 1)
	assert.Equal(t, "o2", bad[0].digest)
	bad = crossCheck([]accepted{res})
	require.Len(t, bad, 1, "the view operation must be among the operations")
}

func TestShardKeysAreKeys(t *testing.T) {
	assert.Equal(t, "test.probe_go2", shardOf("test/probe-go2"))
	assert.Equal(t, "infra.authz", shardOf("infra/authz"))
	assert.Equal(t, stableID("a", "b"), stableID("a", "b"))
	assert.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, stableID("x"))
}

// TestTheModuleIsMergeSafe: the module is compiled into the Go infra shell.
func TestTheModuleIsMergeSafe(t *testing.T) {
	findings, err := mergesafety.CheckDir(".")
	require.NoError(t, err)
	for _, f := range findings {
		t.Errorf("%v", f)
	}
}
