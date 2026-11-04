package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func depth(n int) *int { return &n }

// The management structure's actions and depth (09a's management_unit; security 04's re-delegation, A131).
func delegationUnits() map[string]unitBody {
	all := append([]string{}, allActions...)
	return withIDs(map[string]unitBody{
		"root":   {Root: true, ManagementActions: all, MaxSubdelegationDepth: depth(6)},
		"group":  {Parent: "root", ManagementActions: []string{ActGrant, ActRevoke, ActDelegate}, MaxSubdelegationDepth: depth(3)},
		"entity": {Parent: "group", ManagementActions: []string{ActGrant, ActRevoke, ActDelegate, ActBindRole}, MaxSubdelegationDepth: depth(5)},
		"dept":   {Parent: "entity", ManagementActions: []string{ActGrant}, MaxSubdelegationDepth: depth(0)},
	})
}

// withIDs gives each unit its record's id, as m.units does.
func withIDs(units map[string]unitBody) map[string]unitBody {
	for id, u := range units {
		u.id = id
		units[id] = u
	}
	return units
}

func TestEffectiveActionsAndDepth(t *testing.T) {
	u := delegationUnits()
	assert.ElementsMatch(t, allActions, actionsOf(u, "root"))
	assert.ElementsMatch(t, []string{ActGrant, ActRevoke, ActDelegate}, actionsOf(u, "entity"),
		"bind_role is not the group's: the entity's own list does not give it")
	assert.Equal(t, []string{ActGrant}, actionsOf(u, "dept"))
	assert.Empty(t, actionsOf(u, "nowhere"))
	assert.Equal(t, 6, depthOf(u, "root"))
	assert.Equal(t, 3, depthOf(u, "group"))
	assert.Equal(t, 2, depthOf(u, "entity"), "its own 5, but its parent's 3 leaves it 2")
	assert.Equal(t, 0, depthOf(u, "dept"))
	assert.Equal(t, 0, levelOf(u, "root"))
	assert.Equal(t, 3, levelOf(u, "dept"))
}

func TestManagesWith(t *testing.T) {
	u := delegationUnits()
	s := standing{units: u, held: []string{"dept"}}
	assert.True(t, s.managesWith("dept", ActGrant))
	assert.False(t, s.managesWith("dept", ActRevoke), "the dept's holders may not revoke")
	s.held = []string{"dept", "entity"}
	assert.True(t, s.managesWith("dept", ActRevoke), "the entity's holders revoke below it")
	assert.False(t, s.managesWith("dept", ActBindRole), "the entity lists bind_role, its group does not")
	assert.False(t, s.managesWith("group", ActGrant), "not above what one holds")
}

func TestDelegation(t *testing.T) {
	u := delegationUnits()
	child := func(parent string, d int, actions ...string) unitBody {
		return unitBody{Parent: parent, ManagementActions: actions, MaxSubdelegationDepth: depth(d)}
	}
	cases := []struct {
		name  string
		b     unitBody
		max   int
		whyIn string // a part of why not, "" contained
	}{
		{"within", child("entity", 1, ActGrant, ActRevoke), 6, ""},
		{"an action the parent has not", child("entity", 1, ActGrant, ActBindRole), 6, "bind_role"},
		{"as deep as the parent", child("entity", 2, ActGrant), 6, "depth"},
		{"under a parent of depth 0", child("dept", 0, ActGrant), 6, "depth"},
		{"deeper than the deployment's maximum", child("entity", 0, ActGrant), 2, "maximum"},
	}
	for _, c := range cases {
		why := delegation(u, c.b, c.max)
		if c.whyIn == "" {
			assert.Empty(t, why, c.name)
		} else {
			assert.Contains(t, why, c.whyIn, c.name)
		}
	}
}

func TestUnitShape(t *testing.T) {
	ok := unitBody{Name: "u", Parent: "root", ManagementActions: []string{ActGrant}, MaxSubdelegationDepth: depth(0)}
	assert.Empty(t, unitShape(ok))
	for name, b := range map[string]unitBody{
		"no actions":        {Name: "u", Parent: "root", MaxSubdelegationDepth: depth(0)},
		"an unknown action": {Name: "u", Parent: "root", ManagementActions: []string{"approve"}, MaxSubdelegationDepth: depth(0)},
		"no depth":          {Name: "u", Parent: "root", ManagementActions: []string{ActGrant}},
		"a negative depth":  {Name: "u", Parent: "root", ManagementActions: []string{ActGrant}, MaxSubdelegationDepth: depth(-1)},
	} {
		assert.NotEmpty(t, unitShape(b), name)
	}
}

func TestUnderItself(t *testing.T) {
	u := delegationUnits()
	assert.True(t, underItself(u, "dept", "entity"), "renewing the entity under its own dept")
	assert.True(t, underItself(u, "entity", "entity"))
	assert.False(t, underItself(u, "group", "entity"))
}
