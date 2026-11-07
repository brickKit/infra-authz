package view

import (
	"testing"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	core "github.com/brickKit/infra-authz/v3/internal/core"
	require "github.com/stretchr/testify/require"

	assert "github.com/stretchr/testify/assert"
)

func TestShardKeysAreKeys(t *testing.T) {
	assert.Equal(t, "test.probe_go2", shardOf("test/probe-go2"))
	assert.Equal(t, "infra.authz", shardOf("infra/authz"))
	assert.Equal(t, stableID("a", "b"), stableID("a", "b"))
	assert.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, stableID("x"))
}

func TestOnlyUsableKeysTakePart(t *testing.T) {
	reg, err := core.ParseRegistry("permission\tdemo.order.read\tdemo/orders\npermission\tdemo.order.export\tdemo/orders\t2026-10-01\n" +
		"permission\tdemo.order.cancel\tdemo/orders\n")
	require.NoError(t, err)
	order := &sdkauthz.Resource{Type: "demo.order", Dimensions: map[string]sdkauthz.Dimension{"region": {Kind: sdkauthz.ValueSet}}}
	d := Defined{Resources: map[string]map[string]any{"demo.order": {}}, Declared: map[string]*sdkauthz.Resource{"demo.order": order},
		Operations: map[string]bool{"demo.order.read": true, "demo.order.export": true, "demo.order.archive": true}}
	at := func(op string) sdkauthz.Segment { return oseg(op, all(), nil, jan, "") }
	assert.True(t, d.Usable(at("demo.order.read"), reg))
	assert.False(t, d.Usable(at("demo.order.export"), reg), "retired in the registry")
	assert.False(t, d.Usable(at("demo.order.cancel"), reg), "registered, no longer defined by its owner")
	assert.False(t, d.Usable(at("demo.order.archive"), reg), "defined, not registered")
	other := at("demo.order.read")
	other.ResourceType = "demo.invoice"
	assert.False(t, d.Usable(other, reg), "another component's resource type")
	// FX01: the resource gained a dimension; a grant made before it lacks the atom and is never read as all
	d.Declared["demo.order"] = &sdkauthz.Resource{Type: "demo.order", Dimensions: map[string]sdkauthz.Dimension{
		"region": {Kind: sdkauthz.ValueSet}, "warehouse": {Kind: sdkauthz.ValueSet}}}
	assert.False(t, d.Usable(at("demo.order.read"), reg), "a segment missing the new dimension")
	wide := at("demo.order.read")
	wide.Atoms = map[string]sdkauthz.Atom{"region": all(), "warehouse": all()}
	assert.True(t, d.Usable(wide, reg), "a segment naming every dimension")
}
