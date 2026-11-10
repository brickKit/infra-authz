package effectpoint

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strconv"
	"time"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	"github.com/brickKit/be-sdk-go/v3/audit"
	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/identity"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/jackc/pgx/v5"
)

// Confirmations (security 08, "确认与受保护操作"; 09a's be.security.confirmation): a confirmation binds its object —
// a saved widening's candidate digest, or a tightening's target at a content revision — and the change that applies
// with it uses it, once. Two bases:
//   - holding: another authorization admin whose account is provably active (A123), checked again when the change
//     enters the effect point;
//   - deployment_owner: a signature with the owner's offline key (A124), checked against AUTHZ_OWNER_KEY; it stands
//     in for an independent confirmer on any protected tightening, and on a protected widening only when no
//     authorization admin besides the requester and the object is available.
// A saved widening whose confirmations are complete enters the effect point through its job (T5c).

// ConfirmationValidity is how long a confirmation holds (security 08's parameter table: 72 hours); a record effective
// in the future counts it from that instant.
const ConfirmationValidity = 72 * time.Hour

// Bases of a confirmation, and the confirmer an owner's confirmation is recorded under.
const (
	basisHolding = "holding"
	BasisOwner   = "deployment_owner"
	OwnerName    = "deployment_owner"
)

type ConfirmIn struct {
	Target           string       `json:"target"`
	Disposition      string       `json:"disposition,omitempty"` // a disposition's release (release.go): its revision in expected_revision
	Plan             string       `json:"plan,omitempty"`        // a plan above the threshold (planhttp.go), with the digest it confirms
	PlanDigest       string       `json:"plan_digest,omitempty"`
	ExpectedRevision *RevisionRef `json:"expected_revision,omitempty"`
	Basis            string       `json:"basis,omitempty"`      // holding (the default) or deployment_owner
	ExpiresAt        string       `json:"expires_at,omitempty"` // an owner's confirmation: as signed
	Signature        string       `json:"signature,omitempty"`  // an owner's confirmation
	// an account's status change (accountchange.go): the account, the status it takes, the version it is made on
	Account            string `json:"account,omitempty"`
	TargetState        string `json:"target_state,omitempty"`
	TargetStateVersion *int64 `json:"target_state_version,omitempty"`
	// an account's link to an employee or its end (accounts' links.go): the employee, the account (Account), the
	// action (link, unlink) and the employee's version it is made on
	Employee        string `json:"employee,omitempty"`
	Action          string `json:"action,omitempty"`
	EmployeeVersion *int64 `json:"employee_version,omitempty"`
}

// AdmitConfirmation checks the operation a confirmation of target needs: a saved widening's is a change, which a
// stale source's last view does not admit; a tightening's is a tightening, which it does (P8.29: the second person
// of security 03's two-person rule confirms while the source is stopped).
func AdmitConfirmation(m *core.Base, c *httpx.Context, target string) (context.Context, string, error) {
	s, _ := sdkauthz.From(c.Ctx())
	facts, err := holderFacts(m, c.Ctx(), Request{Target: target})
	if err != nil {
		return nil, "", err
	}
	op := core.OpTighten
	if core.UUIDText.MatchString(target) {
		err = m.RT.DB.Tx(c.Ctx(), func(ctx context.Context, tx db.Tx) error {
			var state string
			err := tx.QueryRow(ctx, "SELECT state FROM authz_record WHERE id = $1", target).Scan(&state)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if state == "awaiting_confirmation" {
				op = core.OpChange
			}
			return err
		})
		if err != nil {
			return nil, "", err
		}
	}
	ctx, _, err := s.Check(c.Ctx(), op, facts)
	if err != nil {
		return nil, "", err
	}
	u, _ := identity.UserFrom(ctx)
	return ctx, u.Subject, nil
}

// BindingOf is what a confirmation of t binds, as the owner would sign it, with its expiry from now: a saved widening's
// candidate digest (from its effective time when that is in the future), or a tightening's target at the content
// revision asked.
func BindingOf(m *core.Base, t *Target, in ConfirmIn) (sdkauthz.OwnerConfirmation, time.Time, error) {
	if t == nil {
		return sdkauthz.OwnerConfirmation{}, time.Time{}, errs.New(errs.ReasonRequestInvalid, "no such record "+in.Target)
	}
	o := sdkauthz.OwnerConfirmation{Deployment: m.Deployment, Target: t.ID}
	until := time.Now().Add(ConfirmationValidity)
	switch t.State {
	case "awaiting_confirmation":
		if t.CandidateDigest == "" {
			return o, until, errs.New(errs.ReasonRequestInvalid, "the saved record has no candidate digest to confirm")
		}
		o.CandidateDigest = t.CandidateDigest
		if t.EffectiveAt != nil && t.EffectiveAt.After(time.Now()) {
			until = t.EffectiveAt.Add(ConfirmationValidity)
		}
	case "active", "held":
		if in.ExpectedRevision == nil {
			return o, until, errs.New(errs.ReasonRequestInvalid, "a tightening's confirmation names the target's revision (expected_revision)")
		}
		if _, err := strconv.ParseInt(in.ExpectedRevision.Value, 10, 64); err != nil {
			return o, until, errs.New(errs.ReasonRequestInvalid, "expected_revision is not a revision")
		}
		o.ExpectedRevision = in.ExpectedRevision.Value
	default:
		return o, until, errs.New(errs.ReasonRequestInvalid, "nothing to confirm on a record "+t.State)
	}
	o.ExpiresAt = canon.Time(until)
	return o, until, nil
}

// Confirm records one confirmation and, when it completes a saved widening's, registers the job that brings it to the
// effect point.
func Confirm(m *core.Base, ctx context.Context, confirmer string, in ConfirmIn) (string, time.Time, error) {
	id := ids.New().String()
	var until time.Time
	err := m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		t, err := LockTarget(ctx, tx, in.Target)
		if err != nil {
			return err
		}
		o, by, err := BindingOf(m, t, in)
		if err != nil {
			return err
		}
		basis, who := basisHolding, confirmer
		switch in.Basis {
		case "", basisHolding:
			units, err := Units(m, ctx, tx)
			if err != nil {
				return err
			}
			affects, err := AffectsAdmins(ctx, tx, units, t)
			if err != nil {
				return err
			}
			// a tightening that does not touch an admin's availability: the second person by the last applied facts
			lastApplied := t.State != "awaiting_confirmation" && !affects
			switch ok, err := ConfirmerEligible(m, ctx, tx, confirmer, lastApplied); {
			case err != nil:
				return err
			case ok == core.Unprovable:
				return errs.New(errs.ReasonAuthorizationUnprovable, "the confirmer's eligibility cannot be proven now")
			case ok == core.Disproven:
				return errs.New(errs.ReasonPermissionDenied, "only another authorization admin confirms (A123)")
			}
			until = by
		case BasisOwner: // the expiry is the one signed (no later than a confirmation may hold)
			at, err := time.Parse(time.RFC3339Nano, in.ExpiresAt)
			if err != nil || !at.After(time.Now()) || at.After(by.Add(time.Minute)) {
				return errs.New(errs.ReasonRequestInvalid, "expires_at is an instant ahead, no later than a confirmation holds")
			}
			o.ExpiresAt = in.ExpiresAt
			key, err := ownerKey(m)
			if err != nil {
				return err
			}
			if !o.Verify(key, in.Signature) {
				return errs.New(errs.ReasonPermissionDenied, "the deployment owner's signature does not verify")
			}
			basis, who, until = BasisOwner, OwnerName, at
			// every use of the owner's key is told to every authorization admin and the registered contacts (security
			// 08); without a notification channel in this version, the audit and an error-level log carry it
			m.RT.Logger.Error("the deployment owner's confirmation was used", "target", t.ID, "type", t.Type, "submitted_by", confirmer)
			op := core.OpTighten // the operation that admitted it (admitConfirmation)
			if t.State == "awaiting_confirmation" {
				op = core.OpChange
			}
			if _, err := m.RT.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: op,
				Outcome: audit.Succeeded, Actor: confirmer, Target: map[string]any{"type": t.Type, "id": t.ID},
				Changes: map[string]any{"action": "owner_confirmation"}}); err != nil {
				return err
			}
		default:
			return errs.New(errs.ReasonRequestInvalid, "basis is holding or deployment_owner")
		}
		var digest, revision any
		if o.CandidateDigest != "" {
			digest = o.CandidateDigest
		} else {
			revision, _ = strconv.ParseInt(o.ExpectedRevision, 10, 64)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO authz_confirmation (id, target, candidate_digest, expected_revision, confirmer,
			basis, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, t.ID, digest, revision, who, basis, until); err != nil {
			return err
		}
		if t.State == "awaiting_confirmation" { // the saved widening goes to the effect point (T5c)
			_, err := m.RT.Work.Enqueue(ctx, tx, JobDue, firing{Record: t.ID, StateRevision: t.StateRevision,
				Trigger: triggerConfirmed})
			return err
		}
		return nil
	})
	return id, until, err
}

// ownerKey is the deployment owner's public key (AUTHZ_OWNER_KEY, PEM); none configured refuses owner confirmations.
func ownerKey(m *core.Base) (ed25519.PublicKey, error) { return PublicKey(m, "AUTHZ_OWNER_KEY") }

// PublicKey reads an Ed25519 public key (PEM, PKIX) from a configuration key: the owner's confirmation key, or the
// recovery key (A124, A129). Absent: refused.
func PublicKey(m *core.Base, name string) (ed25519.PublicKey, error) {
	text := m.RT.Config.Secret(name).Value()
	if text == "" {
		return nil, errs.New(errs.ReasonPermissionDenied, "this deployment has no such key ("+name+")")
	}
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, errors.New(name + " is not PEM")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New(name + " is not an Ed25519 public key")
	}
	return key, nil
}

// ConfirmerEligible: an authorization admin (A123) whose account the identity source proves active now; lastApplied,
// or by the last applied facts (row 22's exemption: security 03's second person on a tightening that does not affect
// an authorization admin's availability).
func ConfirmerEligible(m *core.Base, ctx context.Context, tx db.Tx, principal string, lastApplied bool) (core.Proof, error) {
	_, admin, err := HoldingsOf(ctx, tx, principal)
	if err != nil || !admin {
		return core.Disproven, err
	}
	a, err := accountOf(m, ctx, tx, principal)
	if lastApplied && a.now == core.Unprovable && a.last && !a.quarantined {
		return core.Proven, err
	}
	return a.now, err
}

// confirmationsOf judges the confirmations of a change against its target (security 08, rows 22-24). A confirmation does
// not hold when it is unknown, used, expired, for another object or revision, the requester's or the object's own, by
// a confirmer not eligible now, or the owner's on a widening while another admin is available; it is not provable
// when its confirmer's eligibility cannot be proven now.
//   - a tightening carries its confirmation_ids: any that does not hold makes them invalid, any not provable makes
//     them not provable;
//   - a saved widening has every live confirmation recorded for it: enough of them must hold (one, the parameter
//     table); the others do not count. With none that holds, one not provable means wait (row 22), else invalid.
//
// ids are the ones to mark used when the change applies.
func confirmationsOf(m *core.Base, ctx context.Context, tx db.Tx, list []string, t *Target, requester, object string,
	lastApplied bool, f *core.Facts) ([]string, error) {
	widening := t.State == "awaiting_confirmation" || t.State == "scheduled" // a saved widening, effective later or not
	if widening {
		rows, err := tx.Query(ctx, `SELECT id::text FROM authz_confirmation WHERE target = $1 AND consumed_by_change IS NULL
			AND expires_at > now() ORDER BY confirmed_at`, t.ID)
		if err != nil {
			return nil, err
		}
		if list, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			return nil, err
		}
	}
	if len(list) == 0 {
		return nil, nil
	}
	var holding, invalid, unprovableIDs []string
	for _, id := range list {
		switch st, err := judgeConfirmation(m, ctx, tx, id, t, widening, requester, object, !widening && lastApplied); {
		case err != nil:
			return nil, err
		case st == core.Proven:
			holding = append(holding, id)
		case st == core.Unprovable:
			unprovableIDs = append(unprovableIDs, id)
		default:
			invalid = append(invalid, id)
		}
	}
	f.Confirmation, f.ConfirmersProvable = core.ConfirmValid, true
	if widening && len(holding) > 0 { // only the owner's: the cooling-off may apply (cooling.go)
		if err := tx.QueryRow(ctx, "SELECT bool_and(basis = $2) FROM authz_confirmation WHERE id::text = ANY($1)",
			holding, BasisOwner).Scan(&f.OwnerOnly); err != nil {
			return nil, err
		}
	}
	switch {
	case !widening && len(invalid) > 0, widening && len(holding) == 0 && len(unprovableIDs) == 0:
		f.Confirmation = core.ConfirmInvalid
	case !widening && len(unprovableIDs) > 0, widening && len(holding) == 0:
		f.ConfirmersProvable = false
	}
	if widening {
		return holding, nil
	}
	return list, nil
}

// judgeConfirmation is one confirmation: proven (it holds), unprovable (its confirmer cannot be proven eligible now),
// or disproven (it does not hold).
func judgeConfirmation(m *core.Base, ctx context.Context, tx db.Tx, id string, t *Target, widening bool, requester,
	object string, lastApplied bool) (core.Proof, error) {
	var c struct {
		Target, Confirmer, Basis string
		Revision                 *int64
		Digest                   *string
		Live                     bool
	}
	err := tx.QueryRow(ctx, `SELECT coalesce(target::text, ''), confirmer, basis, expected_revision, candidate_digest,
			consumed_by_change IS NULL AND expires_at > now() FROM authz_confirmation WHERE id::text = $1 FOR UPDATE`, id).
		Scan(&c.Target, &c.Confirmer, &c.Basis, &c.Revision, &c.Digest, &c.Live)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return core.Disproven, nil
	case err != nil:
		return core.Unprovable, err
	}
	bound := widening && c.Digest != nil && *c.Digest == t.CandidateDigest ||
		!widening && c.Revision != nil && *c.Revision == t.Revision
	if !c.Live || c.Target != t.ID || !bound {
		return core.Disproven, nil
	}
	if c.Basis == BasisOwner { // the owner's key, not a person: no eligibility to check (row 22's exemption)
		if !widening {
			return core.Proven, nil
		}
		// an independent person must confirm a protected widening when one is available
		others, err := OthersAvailable(m, ctx, tx, requester, object)
		if err != nil || others {
			return core.Disproven, err
		}
		return core.Proven, nil
	}
	if c.Confirmer == requester || c.Confirmer == object {
		return core.Disproven, nil
	}
	return ConfirmerEligible(m, ctx, tx, c.Confirmer, lastApplied)
}

// OthersAvailable: an authorization admin other than the requester and the object whose account is provably active,
// or one the requester itself made unavailable within the cooling-off (CP108, cooling.go).
func OthersAvailable(m *core.Base, ctx context.Context, tx db.Tx, requester, object string) (bool, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT body->>'holder' FROM authz_record WHERE state = 'active'
		AND record_type = 'management_holding' AND body->>'system_role' = 'authorization_admin' AND NOT coalesce((body->>'confirmation_backfill_pending')::boolean, false)
		AND body->>'holder' <> ALL($1)`, []string{requester, object})
	if err != nil {
		return false, err
	}
	others, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return false, err
	}
	for _, o := range others {
		if a, err := accountOf(m, ctx, tx, o); err != nil || a.now == core.Proven {
			return a.now == core.Proven, err
		}
	}
	return madeUnavailableBy(ctx, tx, requester, requester, object)
}

// useConfirmations marks the confirmations used by the change that applied with them.
func useConfirmations(ctx context.Context, tx db.Tx, list []string, change string) error {
	if len(list) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, "UPDATE authz_confirmation SET consumed_by_change = $2 WHERE id::text = ANY($1)", list, change)
	return err
}
