package effectpoint

import (
	"context"
	"encoding/json"
	"errors"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/identity"
	pgx "github.com/jackc/pgx/v5"
)

// ChangeHTTP takes widenings and neutral changes; a tightening goes to tightenHTTP, under its own operation.
func ChangeHTTP(m *core.Base, c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	var in Request
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	if in.Direction == core.Tighten {
		return errs.New(errs.ReasonRequestInvalid, "a tightening goes to POST /api/authz/tightenings ("+core.OpTighten+")")
	}
	facts, err := holderFacts(m, c.Ctx(), in)
	if err != nil {
		return err
	}
	ctx, _, err := s.Check(c.Ctx(), core.OpChange, facts)
	if err != nil {
		return err
	}
	u, _ := identity.UserFrom(ctx)
	res, err := change(m, ctx, u.Subject, in)
	if err != nil {
		return err
	}
	return answer(c, res)
}

// TightenHTTP takes a tightening of an existing record: a revocation, a narrowing, or ending one not yet effective.
// The operation is tightening_only: admitted on a stale source's last view (P8.29), the requester judged at the effect
// point by the last applied facts within T_tight, with a second person beyond (security 03, A125).
func TightenHTTP(m *core.Base, c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	var in Request
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	if in.Direction != core.Tighten || in.Target == "" {
		return errs.New(errs.ReasonRequestInvalid, "a tightening is direction tighten on its target")
	}
	facts, err := holderFacts(m, c.Ctx(), in)
	if err != nil {
		return err
	}
	ctx, _, err := s.Check(c.Ctx(), core.OpTighten, facts)
	if err != nil {
		return err
	}
	u, _ := identity.UserFrom(ctx)
	res, err := change(m, ctx, u.Subject, in)
	if err != nil {
		return err
	}
	return answer(c, res)
}

// RelinquishHTTP is a principal ending its own grant or holding (D82): a whole record, the requester its grantee or
// holder; the effect point checks the rest as for any tightening.
func RelinquishHTTP(m *core.Base, c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	var in Request
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	if in.Direction != core.Tighten || in.Target == "" || in.Termination != "" || len(in.Candidate) > 0 {
		return errs.New(errs.ReasonRequestInvalid, "a relinquishment ends one whole record: direction tighten and its target, nothing else")
	}
	facts, err := holderFacts(m, c.Ctx(), in)
	if err != nil {
		return err
	}
	ctx, _, err := s.Check(c.Ctx(), core.OpRelinquish, facts) // another's record: not visible, 404
	if err != nil {
		return err
	}
	u, _ := identity.UserFrom(ctx)
	res, err := changeAs(m, ctx, u.Subject, in, true)
	if err != nil {
		return err
	}
	return answer(c, res)
}

// holderFacts are a change's facts for the holder dimension: whose its target is, or whose its candidate would be.
func holderFacts(m *core.Base, ctx context.Context, in Request) (sdkauthz.Facts, error) {
	var holder string
	switch {
	case in.Target != "":
		if !core.UUIDText.MatchString(in.Target) {
			return sdkauthz.Facts{core.Holder: {State: "null"}}, nil
		}
		err := m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
			var h *string
			err := tx.QueryRow(ctx, "SELECT holder FROM authz_record WHERE id = $1", in.Target).Scan(&h)
			if errors.Is(err, pgx.ErrNoRows) || h == nil {
				return nil
			}
			holder = *h
			return err
		})
		if err != nil {
			return nil, err
		}
	case len(in.Candidate) > 0:
		var b struct {
			Grantee string `json:"grantee"`
			Holder  string `json:"holder"`
		}
		_ = json.Unmarshal(in.Candidate, &b)
		holder = b.Grantee + b.Holder
	}
	if holder == "" {
		return sdkauthz.Facts{core.Holder: {State: "null"}}, nil // a unit, a role revision, or no such record: nobody's
	}
	return sdkauthz.Facts{core.Holder: {State: "value", Value: holder}}, nil
}

// answer is a change result on the user surface: a rejection as its error; processing, awaiting confirmation and
// scheduled are accepted for later (202, security 09a); applied and a kept hold are done (200).
func answer(c *httpx.Context, res ChangeResult) error {
	switch res.Outcome {
	case "rejected":
		return errs.New(res.Reason, res.Detail).With("change_key", res.ChangeKey)
	case "processing", "awaiting_confirmation", "scheduled":
		return c.JSON(202, res)
	}
	return c.JSON(200, res)
}

// ChangeByKey answers a query by change key (security 08: when a result is unknown, ask, do not submit again).
func ChangeByKey(m *core.Base, c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	u, _ := identity.UserFrom(c.Ctx())
	// the key is in the caller's own namespace: those who may change or tighten records, or relinquish their own, may ask
	own := sdkauthz.Facts{core.Holder: {State: "value", Value: u.Subject}}
	var ctx context.Context
	var err error
	for _, op := range []string{core.OpChange, core.OpTighten, core.OpRelinquish} {
		if ctx, _, err = s.Check(c.Ctx(), op, own); err == nil {
			break
		}
	}
	if err != nil {
		return err
	}
	key := c.Param("key")
	res := ChangeResult{ChangeKey: key, Outcome: "unbound"}
	err = m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var bound []byte
		err := tx.QueryRow(ctx, "SELECT result FROM authz_change WHERE requested_by = $1 AND change_key = $2",
			u.Subject, key).Scan(&bound)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err == nil {
			err = json.Unmarshal(bound, &res)
		}
		if err == nil {
			res, err = current(ctx, tx, res)
		}
		return err
	})
	if err != nil {
		return err
	}
	return c.JSON(200, res)
}

func RecordsHTTP(m *core.Base, c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	ctx, plan, err := s.List(c.Ctx(), core.OpRead, "r", 1) // $1 is the types; only the records the caller may see (its own, D82, or all)
	if err != nil {
		return err
	}
	types := []string{"management_unit", "management_holding", "role_revision", "grant"}
	if t := c.Query("type"); t != "" {
		types = []string{t}
	}
	var out []map[string]any
	err = m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT r.id::text, r.record_type, r.revision, r.body FROM authz_record r
			WHERE r.state = 'active' AND r.record_type = ANY($1)
				AND (r.valid_from IS NULL OR r.valid_from <= now()) AND (r.valid_until IS NULL OR r.valid_until > now())
				AND (`+plan.Where+`) ORDER BY r.created_at, r.id`, append([]any{types}, plan.Args...)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r core.Record
			if err := rows.Scan(&r.ID, &r.Type, &r.Revision, &r.Body); err != nil {
				return err
			}
			out = append(out, map[string]any{"id": r.ID, "record_type": r.Type, "revision": r.Revision, "body": r.Body})
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	return c.JSON(200, map[string]any{"records": out})
}
