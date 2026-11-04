package authz

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/identity"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/jackc/pgx/v5"
)

// Confirmations (security 08, "确认与受保护操作"; 09a's be.security.confirmation): a confirmer records one for an object
// — a saved widening's candidate, or a tightening's target at a content revision — and the change that applies with
// it uses it, once. Who may confirm by default (A123): another authorization admin whose account is provably active;
// the effect point checks that again when the change enters, with everything else a confirmation must hold.

// ConfirmationValidity is how long a confirmation holds (security 08's parameter table: 72 hours); a record effective
// in the future counts it from that instant.
const ConfirmationValidity = 72 * time.Hour

type confirmIn struct {
	Target           string       `json:"target"`
	ExpectedRevision *revisionRef `json:"expected_revision,omitempty"`
}

func (m *Module) confirmHTTP(c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	var in confirmIn
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	facts, err := m.holderFacts(c.Ctx(), request{Target: in.Target})
	if err != nil {
		return err
	}
	ctx, _, err := s.Check(c.Ctx(), OpChange, facts)
	if err != nil {
		return err
	}
	u, _ := identity.UserFrom(ctx)
	id, until, err := m.confirm(ctx, u.Subject, in)
	if err != nil {
		return err
	}
	return c.JSON(201, map[string]any{"id": id, "expires_at": until.UTC().Format(time.RFC3339Nano)})
}

// confirm records one confirmation by a confirmer eligible now.
func (m *Module) confirm(ctx context.Context, confirmer string, in confirmIn) (string, time.Time, error) {
	id := ids.New().String()
	var until time.Time
	err := m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		t, err := lockTarget(ctx, tx, in.Target)
		if err != nil {
			return err
		}
		if t == nil {
			return errs.New(errs.ReasonRequestInvalid, "no such record "+in.Target)
		}
		switch ok, err := m.confirmerEligible(ctx, tx, confirmer); {
		case err != nil:
			return err
		case ok == unprovable:
			return errs.New(errs.ReasonAuthorizationUnprovable, "the confirmer's eligibility cannot be proven now")
		case ok == disproven:
			return errs.New(errs.ReasonPermissionDenied, "only another authorization admin confirms (A123)")
		}
		var digest, revision any
		until = time.Now().Add(ConfirmationValidity)
		switch t.State {
		case "awaiting_confirmation": // a saved widening: its candidate
			if t.CandidateDigest == "" {
				return errs.New(errs.ReasonRequestInvalid, "the saved record has no candidate digest to confirm")
			}
			digest = t.CandidateDigest
			if t.EffectiveAt != nil && t.EffectiveAt.After(time.Now()) {
				until = t.EffectiveAt.Add(ConfirmationValidity)
			}
		case "active", "held": // a tightening: the target at a content revision
			if in.ExpectedRevision == nil {
				return errs.New(errs.ReasonRequestInvalid, "a tightening's confirmation names the target's revision (expected_revision)")
			}
			rev, err := strconv.ParseInt(in.ExpectedRevision.Value, 10, 64)
			if err != nil {
				return errs.New(errs.ReasonRequestInvalid, "expected_revision is not a revision")
			}
			revision = rev
		default:
			return errs.New(errs.ReasonRequestInvalid, "nothing to confirm on a record "+t.State)
		}
		_, err = tx.Exec(ctx, `INSERT INTO authz_confirmation (id, target, candidate_digest, expected_revision, confirmer,
			basis, expires_at) VALUES ($1, $2, $3, $4, $5, 'holding', $6)`, id, t.ID, digest, revision, confirmer, until)
		return err
	})
	return id, until, err
}

// confirmerEligible: an authorization admin (A123) whose account the identity source proves active now.
func (m *Module) confirmerEligible(ctx context.Context, tx db.Tx, principal string) (proof, error) {
	_, admin, err := holdingsOf(ctx, tx, principal)
	if err != nil || !admin {
		return disproven, err
	}
	acct, _, _, err := m.accountOf(ctx, tx, principal)
	return acct, err
}

// confirmationsOf judges the confirmations a change carries against its target (security 08, rows 22-24): any that
// does not hold — unknown, used, expired, for another object or revision, the requester's or the object's own, a
// confirmer not eligible now — makes them invalid; a confirmer whose eligibility cannot be proven now makes them not
// provable. ids are the ones to mark used when the change applies.
func (m *Module) confirmationsOf(ctx context.Context, tx db.Tx, list []string, t *target, requester string, f *facts) ([]string, error) {
	if len(list) == 0 {
		return nil, nil
	}
	f.Confirmation, f.ConfirmersProvable = confirmValid, true
	object := recordHolder(t)
	for _, id := range list {
		var c struct {
			Target, Confirmer string
			Revision          *int64
			Live              bool
		}
		err := tx.QueryRow(ctx, `SELECT target::text, confirmer, expected_revision,
				consumed_by_change IS NULL AND expires_at > now() FROM authz_confirmation WHERE id::text = $1 FOR UPDATE`, id).
			Scan(&c.Target, &c.Confirmer, &c.Revision, &c.Live)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			f.Confirmation = confirmInvalid
			continue
		case err != nil:
			return nil, err
		}
		if !c.Live || c.Target != t.ID || c.Revision == nil || *c.Revision != t.Revision || c.Confirmer == requester ||
			c.Confirmer == object {
			f.Confirmation = confirmInvalid
			continue
		}
		switch ok, err := m.confirmerEligible(ctx, tx, c.Confirmer); {
		case err != nil:
			return nil, err
		case ok == disproven:
			f.Confirmation = confirmInvalid
		case ok == unprovable:
			f.ConfirmersProvable = false
		}
	}
	return slices.Clone(list), nil
}

// useConfirmations marks the confirmations used by the change that applied with them.
func useConfirmations(ctx context.Context, tx db.Tx, list []string, change string) error {
	if len(list) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, "UPDATE authz_confirmation SET consumed_by_change = $2 WHERE id::text = ANY($1)", list, change)
	return err
}
