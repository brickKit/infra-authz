package authz

import (
	"fmt"
	"slices"
)

// Re-delegation and management actions (09a's management_unit; security 04's "各种管理动作的检查" and "再下放",
// A131). A unit lists the management actions its holders may take in it and below, and how many levels may still be
// made below it; a child's are within its parent's (the action set a subset, the depth smaller), and what a unit
// gives is what every unit above it gives too: an ancestor narrowed narrows its descendants at once.

// Management actions.
const (
	ActGrant    = "grant"               // a grant of segments
	ActRevoke   = "revoke"              // a tightening of a grant (revocation, narrowing, cancellation)
	ActEditRole = "edit_role"           // role revisions (an authorization admin's in this version)
	ActBindRole = "bind_role"           // a grant of a role revision
	ActDelegate = "delegate_management" // child units, management holdings, and their tightenings
	ActShare    = "share_governance"    // institutional shares (not in this version)
)

var allActions = []string{ActGrant, ActRevoke, ActEditRole, ActBindRole, ActDelegate, ActShare}

// DefaultMaxUnitDepth is AUTHZ_MAX_UNIT_DEPTH's default: the levels below the root (group, legal entity, department,
// team, and two to spare).
const DefaultMaxUnitDepth = 6

// unitShape is why a unit candidate is not a valid one, "" valid.
func unitShape(b unitBody) string {
	if len(b.ManagementActions) == 0 {
		return "a management unit lists its management_actions"
	}
	for _, a := range b.ManagementActions {
		if !slices.Contains(allActions, a) {
			return "management action " + a + " is not one of " + fmt.Sprint(allActions)
		}
	}
	if b.MaxSubdelegationDepth == nil || *b.MaxSubdelegationDepth < 0 {
		return "a management unit has a max_subdelegation_depth of 0 or more"
	}
	return ""
}

// chain walks a unit and the units above it to the root; false when it leaves the active units or loops.
func chain(units map[string]unitBody, unit string, each func(unitBody)) bool {
	for u, n := unit, 0; ; u, n = units[u].Parent, n+1 {
		b, ok := units[u]
		if !ok || n > len(units) {
			return false
		}
		each(b)
		if b.Root {
			return true
		}
	}
}

// actionsOf is a unit's effective actions: its own, and every unit's above it.
func actionsOf(units map[string]unitBody, unit string) []string {
	var out []string
	first := true
	ok := chain(units, unit, func(b unitBody) {
		if first {
			out, first = append([]string{}, b.ManagementActions...), false
			return
		}
		out = common(out, b.ManagementActions)
	})
	if !ok {
		return nil
	}
	return out
}

// depthOf is how many levels may still be made below a unit: its own depth, at most one less than its parent's
// effective one; 0 for a unit not under the root.
func depthOf(units map[string]unitBody, unit string) int {
	var depths []int
	if !chain(units, unit, func(b unitBody) {
		d := 0
		if b.MaxSubdelegationDepth != nil {
			d = *b.MaxSubdelegationDepth
		}
		depths = append(depths, d)
	}) {
		return 0
	}
	eff := depths[len(depths)-1] // the root's
	for i := len(depths) - 2; i >= 0; i-- {
		if eff--; depths[i] < eff {
			eff = depths[i]
		}
		if eff < 0 {
			eff = 0
		}
	}
	return eff
}

// levelOf is a unit's level below the root (the root's is 0).
func levelOf(units map[string]unitBody, unit string) int {
	n := -1
	chain(units, unit, func(unitBody) { n++ })
	return n
}

// managesWith: the requester holds this unit or one above it, and that unit's effective actions include action.
func (s standing) managesWith(unit, action string) bool {
	for u, n := unit, 0; n <= len(s.units); u, n = s.units[u].Parent, n+1 {
		if _, ok := s.units[u]; !ok {
			return false
		}
		if slices.ContainsFunc(s.held, func(h string) bool { return sameUnit(s.units, h, u) }) &&
			slices.Contains(actionsOf(s.units, u), action) {
			return true
		}
	}
	return false
}

// delegation is why a child unit is not within its parent's re-delegation (not contained, row 18), "" within: its
// actions within the parent's effective ones, its depth below the parent's, its level within the deployment's maximum.
func delegation(units map[string]unitBody, b unitBody, maxLevel int) string {
	parent := actionsOf(units, b.Parent)
	for _, a := range b.ManagementActions {
		if !slices.Contains(parent, a) {
			return "management action " + a + " is beyond the parent unit's"
		}
	}
	if d := depthOf(units, b.Parent); b.MaxSubdelegationDepth == nil || *b.MaxSubdelegationDepth >= d {
		return fmt.Sprintf("max_subdelegation_depth is not below the parent unit's (%d)", d)
	}
	if level := levelOf(units, b.Parent) + 1; level > maxLevel {
		return fmt.Sprintf("level %d below the root is deeper than the deployment's maximum (%d)", level, maxLevel)
	}
	return ""
}

// underItself: a unit renewed under parent would sit below the record it supersedes (a loop).
func underItself(units map[string]unitBody, parent, predecessor string) bool {
	for u, n := parent, 0; n <= len(units); u, n = units[u].Parent, n+1 {
		b, ok := units[u]
		switch {
		case !ok:
			return false
		case sameUnit(units, u, predecessor):
			return true
		case b.Root:
			return false
		}
	}
	return true // a loop already
}

// actionFor is the management action a tightening of a record of this type takes.
func actionFor(recType string) string {
	if recType == "grant" {
		return ActRevoke
	}
	return ActDelegate
}
