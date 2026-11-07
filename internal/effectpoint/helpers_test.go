package effectpoint

import (
	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
)

// vals, oseg and jan are core's test helpers (internal/core/effective_test.go): a value set, one order segment, a date.
func vals(v ...string) sdkauthz.Atom { return sdkauthz.Atom{Kind: "in", Values: v} }

func oseg(op string, atom sdkauthz.Atom, fields []string, from, until string) sdkauthz.Segment {
	return sdkauthz.Segment{ResourceType: "demo.order", Operation: op, Atoms: map[string]sdkauthz.Atom{"region": atom},
		ReadFields: fields, Valid: sdkauthz.Window{From: from, Until: until}}
}

const jan = "2026-01-01T00:00:00Z"
