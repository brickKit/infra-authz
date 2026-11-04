package authz

import (
	"slices"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
)

// Effective segments (security 08, "有效段的计算"): what a record gives is its segments intersected with its sources
// as they stand now, so a source that narrows narrows the view at once, before any job looks at the record. A
// grant: its segments ∩ its governance unit's current limit; a unit's limit is its managed scope ∩ its parent's
// limit, up to the root (which limits nothing). A segment of a permission key that is not registered, retired, or
// no longer defined by its owner gives nothing. Intersection is closed over security 07's atoms; a pair outside the
// table gives nothing (never more access because a case is hard).

// limit is a unit's effective limit: all (the root), or segments and the operations it may grant.
type limit struct {
	all  bool
	segs []sdkauthz.Segment
	ops  []string
}

// limits computes units' effective limits once per computation.
type limits struct {
	units map[string]unitBody
	memo  map[string]*limit
}

func newLimits(units map[string]unitBody) *limits {
	return &limits{units: units, memo: map[string]*limit{}}
}

// of is a unit's effective limit for no one in particular: a self in a scope meets only another self (a unit's
// scope within its parent's). nil when the unit is not active (nothing is within it) or its chain does not end at
// the root.
func (l *limits) of(unit string) *limit {
	return l.ofFor(unit, "")
}

// ofFor is a unit's effective limit for one grantee: every self along the chain is that grantee (security 07,
// "主体相对的原子"), so a scope's self meets a parent's named set when the grantee is in it.
func (l *limits) ofFor(unit, grantee string) *limit {
	return l.walk(unit, grantee, 0)
}

func (l *limits) walk(unit, grantee string, depth int) *limit {
	key := unit + "\x00" + grantee
	if got, ok := l.memo[key]; ok {
		return got
	}
	u, ok := l.units[unit]
	if !ok || depth > len(l.units) { // ended, or a chain that never reaches the root
		return nil
	}
	var out *limit
	if u.Root {
		out = &limit{all: true}
	} else if parent := l.walk(u.Parent, grantee, depth+1); parent != nil {
		out = &limit{segs: parent.cut(u.ManagedScope, grantee), ops: u.GrantableOperations}
		if !parent.all {
			out.ops = common(u.GrantableOperations, parent.ops)
		}
	}
	l.memo[key] = out
	return out
}

// cut intersects segments with the limit; grantee instantiates self.
func (l *limit) cut(segs []sdkauthz.Segment, grantee string) []sdkauthz.Segment {
	if l == nil {
		return nil
	}
	if l.all {
		return segs
	}
	var out []sdkauthz.Segment
	for _, s := range segs {
		if !slices.Contains(l.ops, s.Operation) {
			continue
		}
		for _, b := range l.segs {
			if x, ok := intersect(s, b, grantee); ok {
				out = append(out, x)
			}
		}
	}
	return out
}

// intersect is one segment within another's bounds: the same resource type and operation, every dimension's atoms
// intersected, the fields and validity in common; ok is false when nothing is left. The result keeps a's source and
// definition (the record it comes from).
func intersect(a, b sdkauthz.Segment, grantee string) (sdkauthz.Segment, bool) {
	if a.ResourceType != b.ResourceType || a.Operation != b.Operation || len(a.Atoms) != len(b.Atoms) {
		return sdkauthz.Segment{}, false
	}
	out := a
	out.Atoms = map[string]sdkauthz.Atom{}
	for dim, x := range a.Atoms {
		y, ok := b.Atoms[dim]
		if !ok {
			return sdkauthz.Segment{}, false // malformed: every dimension has exactly one atom (09a)
		}
		z, ok := atomIntersect(x, y, grantee)
		if !ok {
			return sdkauthz.Segment{}, false
		}
		out.Atoms[dim] = z
	}
	out.ReadFields = common(a.ReadFields, b.ReadFields)
	out.WriteFields = common(a.WriteFields, b.WriteFields)
	w, ok := windowIntersect(a.Valid, b.Valid)
	if !ok {
		return sdkauthz.Segment{}, false
	}
	out.Valid = w
	return out, true
}

func common(a, b []string) []string {
	var out []string
	for _, v := range a {
		if slices.Contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}

// atomIntersect is security 07's intersection of two atoms of one dimension; ok false: empty, or a pair outside the
// table.
func atomIntersect(x, y sdkauthz.Atom, grantee string) (sdkauthz.Atom, bool) {
	switch {
	case x.Kind == "all":
		return y, true
	case y.Kind == "all":
		return x, true
	case x.Kind == "in" && y.Kind == "in":
		v := common(x.Values, y.Values)
		return sdkauthz.Atom{Kind: "in", Values: v}, len(v) > 0
	case x.Kind == "self" && y.Kind == "in":
		return x, grantee != "" && slices.Contains(y.Values, grantee)
	case x.Kind == "in" && y.Kind == "self":
		return y, grantee != "" && slices.Contains(x.Values, grantee)
	case x.Kind == "self" && y.Kind == "self":
		return x, true
	case x.Kind == "tree" && y.Kind == "tree":
		var items []sdkauthz.TreeItem
		for _, a := range x.Items {
			for _, b := range y.Items {
				switch {
				case covers(b, a):
					items = append(items, a)
				case covers(a, b):
					items = append(items, b)
				}
			}
		}
		items = slices.CompactFunc(items, func(a, b sdkauthz.TreeItem) bool { return a == b })
		return sdkauthz.Atom{Kind: "tree", Items: items}, len(items) > 0
	case x.Kind == "interval" && y.Kind == "interval":
		if x.Currency != y.Currency {
			return sdkauthz.Atom{}, false
		}
		out := x
		out.Lo, out.LoClosed = tighterBound(x.Lo, x.LoClosed, y.Lo, y.LoClosed, -1)
		out.Hi, out.HiClosed = tighterBound(x.Hi, x.HiClosed, y.Hi, y.HiClosed, 1)
		return out, nonEmpty(out)
	}
	return sdkauthz.Atom{}, false
}

// tighterBound picks the tighter of two ends; side -1 is the lower end, 1 the upper; nil is unbounded.
func tighterBound(a *string, aClosed *bool, b *string, bClosed *bool, side int) (*string, *bool) {
	switch {
	case a == nil:
		return b, bClosed
	case b == nil:
		return a, aClosed
	}
	cmp, ok := decimalCompare(*a, *b)
	switch {
	case !ok:
		return a, aClosed // not comparable: nonEmpty refuses it below
	case cmp == 0:
		closed := isClosed(aClosed) && isClosed(bClosed)
		return a, &closed
	case cmp*side < 0: // a is inside b's end
		return a, aClosed
	}
	return b, bClosed
}

func nonEmpty(a sdkauthz.Atom) bool {
	if a.Lo == nil || a.Hi == nil {
		return true
	}
	cmp, ok := decimalCompare(*a.Lo, *a.Hi)
	return ok && (cmp < 0 || cmp == 0 && isClosed(a.LoClosed) && isClosed(a.HiClosed))
}

func isClosed(b *bool) bool { return b != nil && *b }

// windowIntersect is the validity in common: the later start, the earlier end; ok false when empty.
func windowIntersect(a, b sdkauthz.Window) (sdkauthz.Window, bool) {
	parse := func(s string) (time.Time, bool) {
		t, err := time.Parse(time.RFC3339Nano, s)
		return t, err == nil
	}
	af, ok1 := parse(a.From)
	bf, ok2 := parse(b.From)
	if !ok1 || !ok2 {
		return sdkauthz.Window{}, false
	}
	out := a
	if bf.After(af) {
		out.From = b.From
	}
	switch {
	case a.Until == "":
		out.Until = b.Until
	case b.Until != "":
		au, ok1 := parse(a.Until)
		bu, ok2 := parse(b.Until)
		if !ok1 || !ok2 {
			return sdkauthz.Window{}, false
		}
		if bu.Before(au) {
			out.Until = b.Until
		}
	}
	if out.Until != "" {
		f, _ := parse(out.From)
		u, _ := parse(out.Until)
		if !u.After(f) {
			return sdkauthz.Window{}, false
		}
	}
	return out, true
}

// computable: every pair of a segment with a limit segment of its operation is in security 07's table (the closure
// job holds a record that is not: held, uncomputable).
func (l *limit) computable(segs []sdkauthz.Segment) bool {
	if l == nil || l.all {
		return true
	}
	for _, s := range segs {
		for _, b := range l.segs {
			if s.ResourceType != b.ResourceType || s.Operation != b.Operation {
				continue
			}
			if len(s.Atoms) != len(b.Atoms) {
				return false
			}
			for dim, x := range s.Atoms {
				y, ok := b.Atoms[dim]
				if !ok || !kindsMeet(x.Kind, y.Kind) {
					return false
				}
			}
		}
	}
	return true
}

// kindsMeet: the pairs atomIntersect has a rule for.
func kindsMeet(x, y string) bool {
	switch {
	case x == "all" || y == "all", x == y && x != "":
		return true
	}
	return x == "self" && y == "in" || x == "in" && y == "self"
}

// covers: every segment is within one limit segment and its operation grantable (otherwise partly outside: the
// record stays effective with the intersection, marked for review).
func (l *limit) covers(segs []sdkauthz.Segment, grantee string) bool {
	if l == nil {
		return false
	}
	if l.all {
		return true
	}
	for _, s := range segs {
		if !slices.Contains(l.ops, s.Operation) ||
			!slices.ContainsFunc(l.segs, func(b sdkauthz.Segment) bool { return contained(s, b, grantee) == nil }) {
			return false
		}
	}
	return true
}
