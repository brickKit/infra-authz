package definitions

import (
	"encoding/json"
	"testing"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/records"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

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

// TestSubmissionRules: the per-record rules of a submission (security 09a): the authority must be the submitter
// (EN21); an attachment category names a field of its resource (EN22); only a manage operation whose only side effect
// is security_change may be tightening only (EN24). Records are the SDK's, edited after sealing.
func TestSubmissionRules(t *testing.T) {
	defs := &sdkauthz.Definitions{Component: "demo/orders",
		Resources: []sdkauthz.Resource{{Type: "demo.order", ViewOperation: "demo.order.read", Dimensions: map[string]sdkauthz.Dimension{},
			Fields: map[string]sdkauthz.Field{"id": {Class: sdkauthz.Ordinary}, "contract_file": {Class: sdkauthz.Ordinary}}}},
		Operations: []sdkauthz.Operation{{Key: "demo.order.read", ResourceType: "demo.order", Purpose: "read", RiskClass: "low"},
			{Key: "demo.order.revoke", ResourceType: "demo.order", Purpose: "manage", RiskClass: "high", SideEffects: []string{"security_change"}}}}
	require.NoError(t, defs.Validate())
	reg, err := core.ParseRegistry("resource_type\tdemo.order\tdemo/orders\npermission\tdemo.order.read\tdemo/orders\n" +
		"permission\tdemo.order.revoke\tdemo/orders\n")
	require.NoError(t, err)
	sealed, err := defs.Records("0190f3a1-0000-7000-8000-0000000000d1", "3.0.0")
	require.NoError(t, err)
	edited := func(key string, edit func(map[string]any)) *authzv3.Definition {
		for _, s := range sealed {
			if s.Key != key {
				continue
			}
			body, err := records.Open(s.RecordType, s.Raw, s.Digest)
			require.NoError(t, err)
			edit(body)
			raw, digest, err := records.Seal(s.RecordType, body)
			require.NoError(t, err)
			return &authzv3.Definition{Record: raw, Digest: digest}
		}
		t.Fatalf("no record %s", key)
		return nil
	}
	m := &core.Base{}
	reasons := func(d *authzv3.Definition) []string {
		_, bad := check(m, "demo/orders", d, reg)
		var out []string
		for _, r := range bad {
			out = append(out, r.reason+": "+r.detail)
		}
		return out
	}
	assert.Empty(t, reasons(edited("demo.order", func(map[string]any) {})), "precondition: the records pass as sealed")

	other := reasons(edited("demo.order", func(b map[string]any) { b["authority"] = "demo/invoices" }))
	require.Len(t, other, 1, "EN21: another component as the authority")
	assert.Contains(t, other[0], "DEFINITION_OWNER_MISMATCH")

	category := func(field string) map[string]any {
		return map[string]any{"contract": map[string]any{"field": field, "max_bytes": json.Number("1048576"),
			"allowed_types": []any{"application/pdf"}, "sensitivity": "normal", "retention_class": "default", "version": "1"}}
	}
	assert.Empty(t, reasons(edited("demo.order", func(b map[string]any) { b["attachment_categories"] = category("contract_file") })),
		"EN22: a category on a field of the resource")
	missing := reasons(edited("demo.order", func(b map[string]any) { b["attachment_categories"] = category("scan") }))
	require.Len(t, missing, 1, "EN22: a category on no field")
	assert.Contains(t, missing[0], "attachment category contract")

	assert.Empty(t, reasons(edited("demo.order.revoke", func(b map[string]any) { b["tightening_only"] = true })),
		"EN24: a manage operation with security_change only may be tightening only")
	for name, edit := range map[string]func(map[string]any){
		"an action operation": func(b map[string]any) { b["tightening_only"], b["purpose"] = true, "action" },
		"another side effect": func(b map[string]any) {
			b["tightening_only"], b["side_effects"] = true, []any{"security_change", "business_write"}
		},
		"no side effect":               func(b map[string]any) { b["tightening_only"], b["side_effects"] = true, []any{} },
		"a business write side effect": func(b map[string]any) { b["tightening_only"], b["side_effects"] = true, []any{"business_write"} },
	} {
		got := reasons(edited("demo.order.revoke", edit))
		require.Len(t, got, 1, "EN24: %s", name)
		assert.Contains(t, got[0], "tightening only", name)
	}
}
