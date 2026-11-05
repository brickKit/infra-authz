package authz

import (
	"context"

	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/recovery"
)

// RecoveryChecks registers what a full recovery asks this member (be-protocol chapter 14): whether the objects this
// member audited are still here, at which revision. The invariants of the authorization state are checked by the
// contract's RecoveryService.Check (6.5), not here.
func (m *Module) RecoveryChecks(c *recovery.Checks) error {
	records := recovery.TablePresence("authz_record", "id", "revision")
	for _, typ := range []string{"management_unit", "management_holding", "role_revision", "grant"} {
		c.Presence(typ, records)
	}
	c.Presence(dispositionType, recovery.TablePresence("authz_disposition", "id", "revision"))
	c.Presence("change_plan", func(ctx context.Context, tx db.Tx, ids []string) (map[string]int64, error) {
		return unversioned(ctx, tx, "SELECT id::text FROM authz_plan WHERE id::text = ANY($1)", ids)
	})
	// an account is the identity member's object; this member's change on it (the account change's confirmation) is
	// covered by the identity side's evidence, so it is answered as present without a revision
	c.Presence("account", func(_ context.Context, _ db.Tx, ids []string) (map[string]int64, error) {
		out := make(map[string]int64, len(ids))
		for _, id := range ids {
			out[id] = 0
		}
		return out, nil
	})
	return nil
}

// unversioned answers presence for objects without a revision: 0 for each id the query finds.
func unversioned(ctx context.Context, tx db.Tx, q string, ids []string) (map[string]int64, error) {
	rows, err := tx.Query(ctx, q, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = 0
	}
	return out, rows.Err()
}
