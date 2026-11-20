package view

import (
	"context"
	"sort"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/identity"
)

// OwnOperations are the operation keys the principal holds now (A177): every key in an effective segment of any
// component's view, computed the way the views are (segments) and judged on the same account status. They carry no
// record's facts, so they say "may": the operation is still decided where it runs. A disabled account holds none;
// an identity source too old to renew any view, or the account not provable, is AUTHORIZATION_UNPROVABLE.
func OwnOperations(m *core.Base, ctx context.Context, principal string) ([]string, error) {
	held := map[string]bool{}
	err := m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, "SELECT component FROM authz_component ORDER BY component")
		if err != nil {
			return err
		}
		var components []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				rows.Close()
				return err
			}
			components = append(components, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		f, err := readFacts(m, ctx, tx)
		if err != nil {
			return err
		}
		for _, c := range components {
			defs, ok, err := definitionsOf(ctx, tx, c)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			if err := segments(ctx, tx, f, c, defs, principal, func(_ string, s sdkauthz.Segment, _ string) error {
				held[s.Operation] = true
				return nil
			}); err != nil {
				return err
			}
		}
		if len(held) == 0 {
			return nil
		}
		accounts, renew, unprovable, err := accountsOf(m, ctx, tx, []string{principal})
		if err != nil {
			return err
		}
		if renew == renewNone || len(unprovable) > 0 {
			return errs.New(errs.ReasonAuthorizationUnprovable, "the account's status cannot be proven right now")
		}
		if a, known := accounts[principal]; !known || a.disabled {
			held = map[string]bool{} // left out of every view, as Verify leaves it out
		}
		return nil
	}, db.Serializable())
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(held))
	for k := range held {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// OwnOperationsHTTP is GET /api/authz/me/operations (A177), the authorization family's standard read
// (contract-infra-authz). Its operation is decided on the caller's own fixed segment; a caller without one holds no
// grant or holding at all, and the answer is that it holds nothing.
func OwnOperationsHTTP(m *core.Base, c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	u, _ := identity.UserFrom(c.Ctx())
	ctx, _, err := s.Check(c.Ctx(), core.OpOwnOperations, sdkauthz.Facts{core.Holder: {State: "value", Value: u.Subject}})
	if errs.Is(err, "be", errs.ReasonNotFound) || errs.Is(err, "be", errs.ReasonPermissionDenied) {
		return c.JSON(200, map[string]any{"operations": []string{}})
	}
	if err != nil {
		return err
	}
	ops, err := OwnOperations(m, ctx, u.Subject)
	if err != nil {
		return err
	}
	return c.JSON(200, map[string]any{"operations": ops})
}
