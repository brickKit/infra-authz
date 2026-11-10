package confirmroutes

import (
	"context"
	"time"

	accounts "github.com/brickKit/infra-authz/v3/internal/accounts"
	core "github.com/brickKit/infra-authz/v3/internal/core"
	effectpoint "github.com/brickKit/infra-authz/v3/internal/effectpoint"
	plans "github.com/brickKit/infra-authz/v3/internal/plans"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/identity"
)

func ConfirmHTTP(m *core.Base, c *httpx.Context) error {
	var in effectpoint.ConfirmIn
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	// a release's confirmation, under the release operation; a plan's, under change; an account's, under tighten for a
	// disablement or a freeze (admitted on a stale view like any tightening) and under change for a re-enable
	// a link's, under change for a link and under tighten for its end
	if in.Disposition != "" || in.Plan != "" || in.Account != "" || in.Employee != "" {
		op, confirm := core.OpRelease, effectpoint.ConfirmDisposition
		switch {
		case in.Employee != "" && in.Action == "unlink":
			op, confirm = core.OpTighten, accounts.ConfirmLink
		case in.Employee != "":
			op, confirm = core.OpChange, accounts.ConfirmLink
		case in.Plan != "":
			op, confirm = core.OpChange, plans.ConfirmPlan
		case in.Account != "" && in.TargetState == "active":
			op, confirm = core.OpChange, accounts.ConfirmAccount
		case in.Account != "":
			op, confirm = core.OpTighten, accounts.ConfirmAccount
		}
		s, _ := sdkauthz.From(c.Ctx())
		ctx, _, err := s.Check(c.Ctx(), op, sdkauthz.Facts{})
		if err != nil {
			return err
		}
		u, _ := identity.UserFrom(ctx)
		var id string
		var until time.Time
		err = m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
			id, until, err = confirm(m, ctx, tx, u.Subject, in)
			return err
		})
		if err != nil {
			return err
		}
		return c.JSON(201, map[string]any{"id": id, "expires_at": canon.Time(until)})
	}
	ctx, u, err := effectpoint.AdmitConfirmation(m, c, in.Target)
	if err != nil {
		return err
	}
	id, until, err := effectpoint.Confirm(m, ctx, u, in)
	if err != nil {
		return err
	}
	return c.JSON(201, map[string]any{"id": id, "expires_at": canon.Time(until)})
}

// OwnerPayloadHTTP answers what the deployment owner signs for a target (sdkauthz.OwnerConfirmation): signing tools
// and seeds ask it, sign offline, and confirm. It tells nothing a confirmer could not read.
func OwnerPayloadHTTP(m *core.Base, c *httpx.Context) error {
	if id := c.Query("disposition"); id != "" { // a release's: the disposition at its revision
		s, _ := sdkauthz.From(c.Ctx())
		ctx, _, err := s.Check(c.Ctx(), core.OpRelease, sdkauthz.Facts{})
		if err != nil {
			return err
		}
		var o sdkauthz.OwnerConfirmation
		err = m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
			d, err := effectpoint.LockDisposition(ctx, tx, id)
			if err == nil && (d == nil || d.State != "active") {
				err = errs.New(errs.ReasonRequestInvalid, "no active disposition "+id)
			}
			if err == nil {
				o, _ = effectpoint.DispositionBinding(m, d)
			}
			return err
		})
		if err != nil {
			return err
		}
		return c.JSON(200, map[string]any{"deployment": o.Deployment, "target": o.Target, "expires_at": o.ExpiresAt,
			"expected_revision": o.ExpectedRevision})
	}
	if employee := c.Query("employee"); employee != "" { // a link's change: the employee, the action on the account at a version
		return accounts.LinkPayloadHTTP(m, c, employee)
	}
	if account := c.Query("account"); account != "" { // an account's status change: the account, the status at a version
		return accounts.AccountPayloadHTTP(m, c, account)
	}
	in := effectpoint.ConfirmIn{Target: c.Query("target")}
	if v := c.Query("expected_revision"); v != "" {
		in.ExpectedRevision = &effectpoint.RevisionRef{Domain: effectpoint.ContentDomain, Value: v}
	}
	ctx, _, err := effectpoint.AdmitConfirmation(m, c, in.Target)
	if err != nil {
		return err
	}
	var o sdkauthz.OwnerConfirmation
	err = m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		t, err := effectpoint.LockTarget(ctx, tx, in.Target)
		if err != nil {
			return err
		}
		o, _, err = effectpoint.BindingOf(m, t, in)
		return err
	})
	if err != nil {
		return err
	}
	out := map[string]any{"deployment": o.Deployment, "target": o.Target, "expires_at": o.ExpiresAt}
	if o.CandidateDigest != "" {
		out["candidate_digest"] = o.CandidateDigest
	} else {
		out["expected_revision"] = o.ExpectedRevision
	}
	return c.JSON(200, out)
}
