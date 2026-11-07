package effectpoint

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/identity"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/jackc/pgx/v5"
)

// Releasing a security disposition (security 08, "解除"; 09a's be.security.disposition_release; T6b): one change at
// the effect point restores every record the disposition still holds (security_hold) — each one effective again,
// or kept held (restore_pending) when nothing of it is left within its limits, retried by the closure job — and only
// then is the disposition released; anything else answered for the release (processing, awaiting confirmation,
// rejected) leaves the disposition and every record as they were. Who may release: someone who may dispose in its
// domain (a disposition from the identity side or an administrator recovery: the root only), not the disposed person.
// Releasing a disposition of an authorization admin is a protected widening: its confirmation binds the disposition
// and its revision.

// ReleaseIn is the release as its requester submits it (09a's disposition_release, the disposition from the path).
type ReleaseIn struct {
	Disposition string       `json:"disposition"`
	Revision    *RevisionRef `json:"disposition_revision,omitempty"`
	SignalRefs  []string     `json:"signal_refs,omitempty"`
}

// dispositionRow is a disposition as the effect point reads it, locked.
type dispositionRow struct {
	ID, State, Origin, Subject, Domain string
	Revision                           int64
}

func LockDisposition(ctx context.Context, tx db.Tx, id string) (*dispositionRow, error) {
	if !core.UUIDText.MatchString(id) {
		return nil, nil
	}
	var d dispositionRow
	err := tx.QueryRow(ctx, `SELECT id::text, state, origin, subject, domain::text, revision FROM authz_disposition
		WHERE id = $1 FOR UPDATE`, id).Scan(&d.ID, &d.State, &d.Origin, &d.Subject, &d.Domain, &d.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &d, err
}

// plannedRelease is what a release writes: the disposition, and the records it still holds.
type plannedRelease struct {
	disp    *dispositionRow
	records []string
	// identity-side: the signal records left after this release removes the ones it names (T6c); while any is
	// left, the disposition stays active and nothing it holds comes back
	left     []string
	identity bool
}

// releasing reads a release: the disposition active and at the revision asked; the requester may release it; the
// records it still holds; a protected widening when its subject is an authorization admin.
func releasing(m *core.Base, ctx context.Context, tx db.Tx, e Entry, s Standing, f *core.Facts, p *plan) (bool, *ChangeResult, error) {
	in := e.Req.Release
	f.Kind = core.RestoreHold
	d, err := LockDisposition(ctx, tx, in.Disposition)
	if err != nil {
		return false, nil, err
	}
	if d == nil {
		return false, invalid("no such disposition " + in.Disposition), nil
	}
	f.FromState = d.State == "active"
	f.FromRevision = in.Revision != nil && in.Revision.Value == strconv.FormatInt(d.Revision, 10)
	rows, err := tx.Query(ctx, `SELECT id::text, record_type FROM authz_record WHERE disposition = $1 AND state = 'held'
		AND hold_reason = 'security_hold' ORDER BY id`, d.ID)
	if err != nil {
		return false, nil, err
	}
	type held struct{ ID, Type string }
	recs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[held])
	if err != nil {
		return false, nil, err
	}
	p.release, p.recType = &plannedRelease{disp: d, identity: d.Origin == "identity_side"}, DispositionType
	if p.release.identity && f.FromState {
		left, ok, err := releaseSignals(ctx, tx, d, in.SignalRefs)
		if err != nil {
			return false, nil, err
		}
		if !ok {
			return false, invalid("an identity-side disposition's release names the signal records it removes (signal_refs), each in its set"), nil
		}
		p.release.left = left
	}
	for _, r := range recs {
		p.release.records = append(p.release.records, r.ID)
		f.ManagementWiden = f.ManagementWiden || r.Type == "management_holding"
	}
	// the subject an authorization admin (its holding held by this disposition, or another): protected
	var admin bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM authz_record WHERE record_type = 'management_holding'
		AND body->>'holder' = $1 AND body->>'system_role' = 'authorization_admin' AND state IN ('active', 'held'))`,
		d.Subject).Scan(&admin); err != nil {
		return false, nil, err
	}
	if admin {
		f.AffectsAdmins, f.TightenNeedsConfirmation = true, true
		if p.confirmed, err = dispositionConfirmations(m, ctx, tx, e.Req.ConfirmationIDs, d, e.Requester, f); err != nil {
			return false, nil, err
		}
	}
	root := ""
	for id, u := range s.units {
		if u.Root && u.ID == id {
			root = id
		}
	}
	domain := d.Domain
	if d.Origin != "admin" { // from the identity side or an administrator recovery: the deployment level only
		domain = root
	}
	return e.Requester != d.Subject && s.manages(domain), nil, nil
}

// release writes a release that applied: every record it still holds effective again, or kept held to be retried
// (restore_pending) when nothing of it is left within its limits; a held record a renewal has since contained ends
// superseded (CP31); the disposition released.
func release(m *core.Base, ctx context.Context, tx db.Tx, e Entry, p plan, change string) (ChangeResult, error) {
	r := p.release
	if r.identity {
		if _, err := tx.Exec(ctx, "UPDATE authz_disposition SET signal_ref = $2, updated_at = now() WHERE id = $1",
			r.disp.ID, NonNil(r.left)); err != nil {
			return ChangeResult{}, err
		}
		if len(r.left) > 0 { // signals left: it stays active, what it holds stays held; the confirmations are used
			if err := useConfirmations(ctx, tx, p.confirmed, change); err != nil {
				return ChangeResult{}, err
			}
			if err := audited(m, ctx, tx, e.operation(), e.Requester, "release", DispositionType, r.disp.ID, "", p.basis); err != nil {
				return ChangeResult{}, err
			}
			return ChangeResult{Outcome: "applied", Record: r.disp.ID,
				NewRevision: &RevisionRef{Domain: DispositionDomain, Value: strconv.FormatInt(r.disp.Revision, 10)}}, nil
		}
	}
	if err := ReleaseDisposition(m, ctx, tx, r.disp.ID, r.records, e.Requester, change); err != nil {
		return ChangeResult{}, err
	}
	if err := useConfirmations(ctx, tx, p.confirmed, change); err != nil {
		return ChangeResult{}, err
	}
	rev, err := applied(m, ctx, tx, e.operation(), e.Requester, "release", DispositionType, r.disp.ID, p.basis)
	if err != nil {
		return ChangeResult{}, err
	}
	return ChangeResult{Outcome: "applied", Record: r.disp.ID,
		NewRevision:       &RevisionRef{Domain: DispositionDomain, Value: strconv.FormatInt(r.disp.Revision, 10)},
		SecurityRevisions: []RevisionRef{{Domain: core.SecurityDomain, Value: strconv.FormatInt(rev, 10)}}}, nil
}

// restorable: something of a held record is left within its limits now (a grant's effective segments; a management
// holding's unit active).
func restorable(t *Target, lims *core.Limits) bool {
	switch t.Type {
	case "grant":
		var b core.GrantBody
		if json.Unmarshal(t.Body, &b) != nil {
			return false
		}
		lim := lims.OfFor(b.GovernanceUnit, b.Grantee)
		return lim != nil && (b.RoleRevision != "" || len(lim.Cut(b.Segments, b.Grantee)) > 0)
	case "management_holding":
		var h core.HoldingBody
		return json.Unmarshal(t.Body, &h) == nil && lims.Of(h.Unit) != nil
	}
	return true
}

// releasedOverBudget: a grant coming back from a disposition would be over a budget with what its grantee holds now.
func releasedOverBudget(ctx context.Context, tx db.Tx, t *Target) (string, error) {
	var b core.GrantBody
	if t.Type != "grant" || json.Unmarshal(t.Body, &b) != nil {
		return "", nil
	}
	return grantOverBudget(ctx, tx, b) // it is held until it comes back: it does not count against itself
}

// dispositionConfirmations judges the confirmations a release of an admin's disposition carries (rows 21-24): each
// bound to this disposition at its revision, live, not the requester's or the subject's; a holding's confirmer an
// authorization admin proven now; the owner's only when no other admin is available (a release is a widening).
func dispositionConfirmations(m *core.Base, ctx context.Context, tx db.Tx, list []string, d *dispositionRow, requester string,
	f *core.Facts) ([]string, error) {
	if len(list) == 0 {
		return nil, nil
	}
	f.Confirmation, f.ConfirmersProvable = core.ConfirmValid, true
	for _, id := range list {
		var c struct {
			Disposition, Confirmer, Basis string
			Revision                      int64
			Live                          bool
		}
		err := tx.QueryRow(ctx, `SELECT coalesce(disposition::text, ''), confirmer, basis, coalesce(disposition_revision, 0),
			consumed_by_change IS NULL AND expires_at > now() FROM authz_confirmation WHERE id::text = $1 FOR UPDATE`, id).
			Scan(&c.Disposition, &c.Confirmer, &c.Basis, &c.Revision, &c.Live)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			f.Confirmation = core.ConfirmInvalid
			continue
		case err != nil:
			return nil, err
		}
		if !c.Live || c.Disposition != d.ID || c.Revision != d.Revision || c.Confirmer == requester || c.Confirmer == d.Subject {
			f.Confirmation = core.ConfirmInvalid
			continue
		}
		if c.Basis == BasisOwner {
			others, err := OthersAvailable(m, ctx, tx, requester, d.Subject)
			if err != nil {
				return nil, err
			}
			if others {
				f.Confirmation = core.ConfirmInvalid
			}
			continue
		}
		switch ok, err := ConfirmerEligible(m, ctx, tx, c.Confirmer, false); {
		case err != nil:
			return nil, err
		case ok == core.Unprovable:
			f.ConfirmersProvable = false
		case ok == core.Disproven:
			f.Confirmation = core.ConfirmInvalid
		}
	}
	return list, nil
}

// ConfirmerBasis checks who confirms an object that is not a record (a disposition's release, a plan): another
// authorization admin proven now (A123), or the deployment owner's signature over o (A124); until is how long it holds.
func ConfirmerBasis(m *core.Base, ctx context.Context, tx db.Tx, confirmer string, in ConfirmIn, o sdkauthz.OwnerConfirmation,
	until time.Time, lastApplied bool) (basis, who string, _ time.Time, err error) {
	switch in.Basis {
	case "", basisHolding:
		switch ok, err := ConfirmerEligible(m, ctx, tx, confirmer, lastApplied); {
		case err != nil:
			return "", "", until, err
		case ok == core.Unprovable:
			return "", "", until, errs.New(errs.ReasonAuthorizationUnprovable, "the confirmer's eligibility cannot be proven now")
		case ok == core.Disproven:
			return "", "", until, errs.New(errs.ReasonPermissionDenied, "only another authorization admin confirms (A123)")
		}
		return basisHolding, confirmer, until, nil
	case BasisOwner:
		at, err := time.Parse(time.RFC3339Nano, in.ExpiresAt)
		if err != nil || !at.After(time.Now()) || at.After(until.Add(time.Minute)) {
			return "", "", until, errs.New(errs.ReasonRequestInvalid, "expires_at is an instant ahead, no later than a confirmation holds")
		}
		o.ExpiresAt = in.ExpiresAt
		key, err := ownerKey(m)
		if err != nil {
			return "", "", until, err
		}
		if !o.Verify(key, in.Signature) {
			return "", "", until, errs.New(errs.ReasonPermissionDenied, "the deployment owner's signature does not verify")
		}
		m.RT.Logger.Error("the deployment owner's confirmation was used", "object", o.Target, "submitted_by", confirmer)
		return BasisOwner, OwnerName, at, nil
	}
	return "", "", until, errs.New(errs.ReasonRequestInvalid, "basis is holding or deployment_owner")
}

// DispositionBinding is what a confirmation of a release binds, as the owner would sign it: the disposition at its
// revision, with its expiry from now.
func DispositionBinding(m *core.Base, d *dispositionRow) (sdkauthz.OwnerConfirmation, time.Time) {
	until := time.Now().Add(ConfirmationValidity)
	return sdkauthz.OwnerConfirmation{Deployment: m.Deployment, Target: d.ID, ExpectedRevision: strconv.FormatInt(d.Revision, 10),
		ExpiresAt: canon.Time(until)}, until
}

// ConfirmDisposition records a confirmation of a disposition's release (holding or the owner's signature).
func ConfirmDisposition(m *core.Base, ctx context.Context, tx db.Tx, confirmer string, in ConfirmIn) (string, time.Time, error) {
	d, err := LockDisposition(ctx, tx, in.Disposition)
	if err != nil {
		return "", time.Time{}, err
	}
	if d == nil || d.State != "active" {
		return "", time.Time{}, errs.New(errs.ReasonRequestInvalid, "no active disposition "+in.Disposition)
	}
	if in.ExpectedRevision == nil || in.ExpectedRevision.Value != strconv.FormatInt(d.Revision, 10) {
		return "", time.Time{}, errs.New(errs.ReasonRequestInvalid, "a release's confirmation names the disposition's revision (expected_revision)")
	}
	o, until := DispositionBinding(m, d)
	basis, who, until, err := ConfirmerBasis(m, ctx, tx, confirmer, in, o, until, false)
	if err != nil {
		return "", time.Time{}, err
	}
	id := ids.New().String()
	_, err = tx.Exec(ctx, `INSERT INTO authz_confirmation (id, disposition, disposition_revision, confirmer, basis, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, id, d.ID, d.Revision, who, basis, until)
	return id, until, err
}

// ReleaseHTTP takes a release of the disposition in the path: 09a's disposition_release (its key, the disposition's
// revision, its confirmations).
func ReleaseHTTP(m *core.Base, c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	var in struct {
		ChangeKey       string       `json:"change_key"`
		Revision        *RevisionRef `json:"disposition_revision,omitempty"`
		SignalRefs      []string     `json:"signal_refs,omitempty"`
		ConfirmationIDs []string     `json:"confirmation_ids,omitempty"`
	}
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	ctx, _, err := s.Check(c.Ctx(), core.OpRelease, sdkauthz.Facts{})
	if err != nil {
		return err
	}
	u, _ := identity.UserFrom(ctx)
	res, err := change(m, ctx, u.Subject, Request{ChangeKey: in.ChangeKey, Direction: "release", ConfirmationIDs: in.ConfirmationIDs,
		Release: &ReleaseIn{Disposition: c.Param("id"), Revision: in.Revision, SignalRefs: in.SignalRefs}})
	if err != nil {
		return err
	}
	return answer(c, res)
}

// ReleaseDisposition brings back what a disposition still holds and releases it: each record effective again, ended
// superseded when a renewal contains it (CP31), or kept held (restore_pending) when nothing of it is left within its
// limits (CP66). A release and an administrator recovery's release both do it.
func ReleaseDisposition(m *core.Base, ctx context.Context, tx db.Tx, id string, records []string, by, change string) error {
	units, err := Units(m, ctx, tx)
	if err != nil {
		return err
	}
	lims := core.NewLimits(units)
	for _, r := range records {
		t, err := LockTarget(ctx, tx, r)
		if err != nil {
			return err
		}
		var renewed bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM authz_record WHERE predecessor = $1 AND state = 'active')",
			r).Scan(&renewed); err != nil {
			return err
		}
		over, err := releasedOverBudget(ctx, tx, t)
		if err != nil {
			return err
		}
		state, endReason, holdReason := "active", "", ""
		switch {
		case renewed:
			state, endReason = "ended", "superseded"
		case !restorable(t, lims) || over != "":
			// nothing left within its limits, or over a budget now (it did not count while held: row 26): kept held,
			// for the closure job's restore to try again
			state, holdReason = "held", "restore_pending"
		}
		if _, err := Transition(m, ctx, tx, r, state, endReason, holdReason, change, ""); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE authz_record SET disposition = NULL WHERE id = $1 AND state <> 'held'", r); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE authz_disposition SET state = 'released', released_by = $2, updated_at = now()
		WHERE id = $1`, id, by)
	return err
}
