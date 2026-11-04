package authz

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strconv"
	"time"

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
	basisOwner   = "deployment_owner"
	ownerName    = "deployment_owner"
)

type confirmIn struct {
	Target           string       `json:"target"`
	Disposition      string       `json:"disposition,omitempty"` // a disposition's release (release.go): its revision in expected_revision
	ExpectedRevision *revisionRef `json:"expected_revision,omitempty"`
	Basis            string       `json:"basis,omitempty"`      // holding (the default) or deployment_owner
	ExpiresAt        string       `json:"expires_at,omitempty"` // an owner's confirmation: as signed
	Signature        string       `json:"signature,omitempty"`  // an owner's confirmation
}

func (m *Module) confirmHTTP(c *httpx.Context) error {
	var in confirmIn
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	if in.Disposition != "" { // a release's confirmation: under the release operation
		s, _ := sdkauthz.From(c.Ctx())
		ctx, _, err := s.Check(c.Ctx(), OpRelease, sdkauthz.Facts{})
		if err != nil {
			return err
		}
		u, _ := identity.UserFrom(ctx)
		var id string
		var until time.Time
		err = m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
			id, until, err = m.confirmDisposition(ctx, tx, u.Subject, in)
			return err
		})
		if err != nil {
			return err
		}
		return c.JSON(201, map[string]any{"id": id, "expires_at": canon.Time(until)})
	}
	ctx, u, err := m.admitConfirmation(c, in.Target)
	if err != nil {
		return err
	}
	id, until, err := m.confirm(ctx, u, in)
	if err != nil {
		return err
	}
	return c.JSON(201, map[string]any{"id": id, "expires_at": canon.Time(until)})
}

// ownerPayloadHTTP answers what the deployment owner signs for a target (sdkauthz.OwnerConfirmation): signing tools
// and seeds ask it, sign offline, and confirm. It tells nothing a confirmer could not read.
func (m *Module) ownerPayloadHTTP(c *httpx.Context) error {
	if id := c.Query("disposition"); id != "" { // a release's: the disposition at its revision
		s, _ := sdkauthz.From(c.Ctx())
		ctx, _, err := s.Check(c.Ctx(), OpRelease, sdkauthz.Facts{})
		if err != nil {
			return err
		}
		var o sdkauthz.OwnerConfirmation
		err = m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
			d, err := lockDisposition(ctx, tx, id)
			if err == nil && (d == nil || d.State != "active") {
				err = errs.New(errs.ReasonRequestInvalid, "no active disposition "+id)
			}
			if err == nil {
				o, _ = m.dispositionBinding(d)
			}
			return err
		})
		if err != nil {
			return err
		}
		return c.JSON(200, map[string]any{"deployment": o.Deployment, "target": o.Target, "expires_at": o.ExpiresAt,
			"expected_revision": o.ExpectedRevision})
	}
	in := confirmIn{Target: c.Query("target")}
	if v := c.Query("expected_revision"); v != "" {
		in.ExpectedRevision = &revisionRef{Domain: contentDomain, Value: v}
	}
	ctx, _, err := m.admitConfirmation(c, in.Target)
	if err != nil {
		return err
	}
	var o sdkauthz.OwnerConfirmation
	err = m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		t, err := lockTarget(ctx, tx, in.Target)
		if err != nil {
			return err
		}
		o, _, err = m.bindingOf(t, in)
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

// admitConfirmation checks the operation a confirmation of target needs: a saved widening's is a change, which a
// stale source's last view does not admit; a tightening's is a tightening, which it does (P8.29: the second person
// of security 03's two-person rule confirms while the source is stopped).
func (m *Module) admitConfirmation(c *httpx.Context, target string) (context.Context, string, error) {
	s, _ := sdkauthz.From(c.Ctx())
	facts, err := m.holderFacts(c.Ctx(), request{Target: target})
	if err != nil {
		return nil, "", err
	}
	op := OpTighten
	if uuidText.MatchString(target) {
		err = m.rt.DB.Tx(c.Ctx(), func(ctx context.Context, tx db.Tx) error {
			var state string
			err := tx.QueryRow(ctx, "SELECT state FROM authz_record WHERE id = $1", target).Scan(&state)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if state == "awaiting_confirmation" {
				op = OpChange
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

// bindingOf is what a confirmation of t binds, as the owner would sign it, with its expiry from now: a saved widening's
// candidate digest (from its effective time when that is in the future), or a tightening's target at the content
// revision asked.
func (m *Module) bindingOf(t *target, in confirmIn) (sdkauthz.OwnerConfirmation, time.Time, error) {
	if t == nil {
		return sdkauthz.OwnerConfirmation{}, time.Time{}, errs.New(errs.ReasonRequestInvalid, "no such record "+in.Target)
	}
	o := sdkauthz.OwnerConfirmation{Deployment: m.deployment, Target: t.ID}
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

// confirm records one confirmation and, when it completes a saved widening's, registers the job that brings it to the
// effect point.
func (m *Module) confirm(ctx context.Context, confirmer string, in confirmIn) (string, time.Time, error) {
	id := ids.New().String()
	var until time.Time
	err := m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		t, err := lockTarget(ctx, tx, in.Target)
		if err != nil {
			return err
		}
		o, by, err := m.bindingOf(t, in)
		if err != nil {
			return err
		}
		basis, who := basisHolding, confirmer
		switch in.Basis {
		case "", basisHolding:
			units, err := m.units(ctx, tx)
			if err != nil {
				return err
			}
			affects, err := affectsAdmins(ctx, tx, units, t)
			if err != nil {
				return err
			}
			// a tightening that does not touch an admin's availability: the second person by the last applied facts
			lastApplied := t.State != "awaiting_confirmation" && !affects
			switch ok, err := m.confirmerEligible(ctx, tx, confirmer, lastApplied); {
			case err != nil:
				return err
			case ok == unprovable:
				return errs.New(errs.ReasonAuthorizationUnprovable, "the confirmer's eligibility cannot be proven now")
			case ok == disproven:
				return errs.New(errs.ReasonPermissionDenied, "only another authorization admin confirms (A123)")
			}
			until = by
		case basisOwner: // the expiry is the one signed (no later than a confirmation may hold)
			at, err := time.Parse(time.RFC3339Nano, in.ExpiresAt)
			if err != nil || !at.After(time.Now()) || at.After(by.Add(time.Minute)) {
				return errs.New(errs.ReasonRequestInvalid, "expires_at is an instant ahead, no later than a confirmation holds")
			}
			o.ExpiresAt = in.ExpiresAt
			key, err := m.ownerKey()
			if err != nil {
				return err
			}
			if !o.Verify(key, in.Signature) {
				return errs.New(errs.ReasonPermissionDenied, "the deployment owner's signature does not verify")
			}
			basis, who, until = basisOwner, ownerName, at
			// every use of the owner's key is told to every authorization admin and the registered contacts (security
			// 08); without a notification channel in this version, the audit and an error-level log carry it
			m.rt.Logger.Error("the deployment owner's confirmation was used", "target", t.ID, "type", t.Type, "submitted_by", confirmer)
			op := OpTighten // the operation that admitted it (admitConfirmation)
			if t.State == "awaiting_confirmation" {
				op = OpChange
			}
			if _, err := m.rt.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: op,
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
			_, err := m.rt.Work.Enqueue(ctx, tx, JobDue, firing{Record: t.ID, StateRevision: t.StateRevision,
				Trigger: triggerConfirmed})
			return err
		}
		return nil
	})
	return id, until, err
}

// ownerKey is the deployment owner's public key (AUTHZ_OWNER_KEY, PEM); none configured refuses owner confirmations.
func (m *Module) ownerKey() (ed25519.PublicKey, error) { return m.publicKey("AUTHZ_OWNER_KEY") }

// publicKey reads an Ed25519 public key (PEM, PKIX) from a configuration key: the owner's confirmation key, or the
// recovery key (A124, A129). Absent: refused.
func (m *Module) publicKey(name string) (ed25519.PublicKey, error) {
	text := m.rt.Config.Secret(name).Value()
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

// confirmerEligible: an authorization admin (A123) whose account the identity source proves active now; lastApplied,
// or by the last applied facts (row 22's exemption: security 03's second person on a tightening that does not affect
// an authorization admin's availability).
func (m *Module) confirmerEligible(ctx context.Context, tx db.Tx, principal string, lastApplied bool) (proof, error) {
	_, admin, err := holdingsOf(ctx, tx, principal)
	if err != nil || !admin {
		return disproven, err
	}
	a, err := m.accountOf(ctx, tx, principal)
	if lastApplied && a.now == unprovable && a.last && !a.quarantined {
		return proven, err
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
func (m *Module) confirmationsOf(ctx context.Context, tx db.Tx, list []string, t *target, requester, object string,
	lastApplied bool, f *facts) ([]string, error) {
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
		switch st, err := m.judgeConfirmation(ctx, tx, id, t, widening, requester, object, !widening && lastApplied); {
		case err != nil:
			return nil, err
		case st == proven:
			holding = append(holding, id)
		case st == unprovable:
			unprovableIDs = append(unprovableIDs, id)
		default:
			invalid = append(invalid, id)
		}
	}
	f.Confirmation, f.ConfirmersProvable = confirmValid, true
	if widening && len(holding) > 0 { // only the owner's: the cooling-off may apply (cooling.go)
		if err := tx.QueryRow(ctx, "SELECT bool_and(basis = $2) FROM authz_confirmation WHERE id::text = ANY($1)",
			holding, basisOwner).Scan(&f.OwnerOnly); err != nil {
			return nil, err
		}
	}
	switch {
	case !widening && len(invalid) > 0, widening && len(holding) == 0 && len(unprovableIDs) == 0:
		f.Confirmation = confirmInvalid
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
func (m *Module) judgeConfirmation(ctx context.Context, tx db.Tx, id string, t *target, widening bool, requester,
	object string, lastApplied bool) (proof, error) {
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
		return disproven, nil
	case err != nil:
		return unprovable, err
	}
	bound := widening && c.Digest != nil && *c.Digest == t.CandidateDigest ||
		!widening && c.Revision != nil && *c.Revision == t.Revision
	if !c.Live || c.Target != t.ID || !bound {
		return disproven, nil
	}
	if c.Basis == basisOwner { // the owner's key, not a person: no eligibility to check (row 22's exemption)
		if !widening {
			return proven, nil
		}
		// an independent person must confirm a protected widening when one is available
		others, err := m.othersAvailable(ctx, tx, requester, object)
		if err != nil || others {
			return disproven, err
		}
		return proven, nil
	}
	if c.Confirmer == requester || c.Confirmer == object {
		return disproven, nil
	}
	return m.confirmerEligible(ctx, tx, c.Confirmer, lastApplied)
}

// othersAvailable: an authorization admin other than the requester and the object whose account is provably active,
// or one the requester itself made unavailable within the cooling-off (CP108, cooling.go).
func (m *Module) othersAvailable(ctx context.Context, tx db.Tx, requester, object string) (bool, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT body->>'holder' FROM authz_record WHERE state = 'active'
		AND record_type = 'management_holding' AND body->>'system_role' = 'authorization_admin'
		AND body->>'holder' <> ALL($1)`, []string{requester, object})
	if err != nil {
		return false, err
	}
	others, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return false, err
	}
	for _, o := range others {
		if a, err := m.accountOf(ctx, tx, o); err != nil || a.now == proven {
			return a.now == proven, err
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
