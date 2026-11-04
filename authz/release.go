package authz

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

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

// releaseIn is the release as its requester submits it (09a's disposition_release, the disposition from the path).
type releaseIn struct {
	Disposition string       `json:"disposition"`
	Revision    *revisionRef `json:"disposition_revision,omitempty"`
	SignalRefs  []string     `json:"signal_refs,omitempty"`
}

// dispositionRow is a disposition as the effect point reads it, locked.
type dispositionRow struct {
	ID, State, Origin, Subject, Domain string
	Revision                           int64
}

func lockDisposition(ctx context.Context, tx db.Tx, id string) (*dispositionRow, error) {
	if !uuidText.MatchString(id) {
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
}

// releasing reads a release: the disposition active and at the revision asked; the requester may release it; the
// records it still holds; a protected widening when its subject is an authorization admin.
func (m *Module) releasing(ctx context.Context, tx db.Tx, e entry, s standing, f *facts, p *plan) (bool, *changeResult, error) {
	in := e.req.Release
	f.Kind = RestoreHold
	d, err := lockDisposition(ctx, tx, in.Disposition)
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
	p.release, p.recType = &plannedRelease{disp: d}, dispositionType
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
		if p.confirmed, err = m.dispositionConfirmations(ctx, tx, e.req.ConfirmationIDs, d, e.requester, f); err != nil {
			return false, nil, err
		}
	}
	root := ""
	for id, u := range s.units {
		if u.Root && u.id == id {
			root = id
		}
	}
	domain := d.Domain
	if d.Origin != "admin" { // from the identity side or an administrator recovery: the deployment level only
		domain = root
	}
	return e.requester != d.Subject && s.manages(domain), nil, nil
}

// release writes a release that applied: every record it still holds effective again, or kept held to be retried
// (restore_pending) when nothing of it is left within its limits; a held record a renewal has since contained ends
// superseded (CP31); the disposition released.
func (m *Module) release(ctx context.Context, tx db.Tx, e entry, p plan, change string) (changeResult, error) {
	r := p.release
	units, err := m.units(ctx, tx)
	if err != nil {
		return changeResult{}, err
	}
	lims := newLimits(units)
	for _, id := range r.records {
		t, err := lockTarget(ctx, tx, id)
		if err != nil {
			return changeResult{}, err
		}
		var renewed bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM authz_record WHERE predecessor = $1 AND state = 'active')",
			id).Scan(&renewed); err != nil {
			return changeResult{}, err
		}
		state, endReason, holdReason := "active", "", ""
		switch {
		case renewed:
			state, endReason = "ended", "superseded"
		case !restorable(t, lims):
			state, holdReason = "held", "restore_pending"
		}
		if _, err := m.transition(ctx, tx, id, state, endReason, holdReason, change, ""); err != nil {
			return changeResult{}, err
		}
		if _, err := tx.Exec(ctx, "UPDATE authz_record SET disposition = NULL WHERE id = $1 AND state <> 'held'", id); err != nil {
			return changeResult{}, err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE authz_disposition SET state = 'released', released_by = $2, updated_at = now()
		WHERE id = $1`, r.disp.ID, e.requester); err != nil {
		return changeResult{}, err
	}
	if err := useConfirmations(ctx, tx, p.confirmed, change); err != nil {
		return changeResult{}, err
	}
	rev, err := m.applied(ctx, tx, e.operation(), e.requester, "release", dispositionType, r.disp.ID, p.basis)
	if err != nil {
		return changeResult{}, err
	}
	return changeResult{Outcome: "applied", Record: r.disp.ID,
		NewRevision:       &revisionRef{Domain: dispositionDomain, Value: strconv.FormatInt(r.disp.Revision, 10)},
		SecurityRevisions: []revisionRef{{Domain: SecurityDomain, Value: strconv.FormatInt(rev, 10)}}}, nil
}

// restorable: something of a held record is left within its limits now (a grant's effective segments; a management
// holding's unit active).
func restorable(t *target, lims *limits) bool {
	switch t.Type {
	case "grant":
		var b grantBody
		if json.Unmarshal(t.Body, &b) != nil {
			return false
		}
		lim := lims.of(b.GovernanceUnit)
		return lim != nil && (b.RoleRevision != "" || len(lim.cut(b.Segments, b.Grantee)) > 0)
	case "management_holding":
		var h holdingBody
		return json.Unmarshal(t.Body, &h) == nil && lims.of(h.Unit) != nil
	}
	return true
}

// dispositionConfirmations judges the confirmations a release of an admin's disposition carries (rows 21-24): each
// bound to this disposition at its revision, live, not the requester's or the subject's; a holding's confirmer an
// authorization admin proven now; the owner's only when no other admin is available (a release is a widening).
func (m *Module) dispositionConfirmations(ctx context.Context, tx db.Tx, list []string, d *dispositionRow, requester string,
	f *facts) ([]string, error) {
	if len(list) == 0 {
		return nil, nil
	}
	f.Confirmation, f.ConfirmersProvable = confirmValid, true
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
			f.Confirmation = confirmInvalid
			continue
		case err != nil:
			return nil, err
		}
		if !c.Live || c.Disposition != d.ID || c.Revision != d.Revision || c.Confirmer == requester || c.Confirmer == d.Subject {
			f.Confirmation = confirmInvalid
			continue
		}
		if c.Basis == basisOwner {
			others, err := m.othersAvailable(ctx, tx, requester, d.Subject)
			if err != nil {
				return nil, err
			}
			if others {
				f.Confirmation = confirmInvalid
			}
			continue
		}
		switch ok, err := m.confirmerEligible(ctx, tx, c.Confirmer, false); {
		case err != nil:
			return nil, err
		case ok == unprovable:
			f.ConfirmersProvable = false
		case ok == disproven:
			f.Confirmation = confirmInvalid
		}
	}
	return list, nil
}

// dispositionBinding is what a confirmation of a release binds, as the owner would sign it: the disposition at its
// revision, with its expiry from now.
func (m *Module) dispositionBinding(d *dispositionRow) (sdkauthz.OwnerConfirmation, time.Time) {
	until := time.Now().Add(ConfirmationValidity)
	return sdkauthz.OwnerConfirmation{Deployment: m.deployment, Target: d.ID, ExpectedRevision: strconv.FormatInt(d.Revision, 10),
		ExpiresAt: canon.Time(until)}, until
}

// confirmDisposition records a confirmation of a disposition's release (holding or the owner's signature).
func (m *Module) confirmDisposition(ctx context.Context, tx db.Tx, confirmer string, in confirmIn) (string, time.Time, error) {
	d, err := lockDisposition(ctx, tx, in.Disposition)
	if err != nil {
		return "", time.Time{}, err
	}
	if d == nil || d.State != "active" {
		return "", time.Time{}, errs.New(errs.ReasonRequestInvalid, "no active disposition "+in.Disposition)
	}
	if in.ExpectedRevision == nil || in.ExpectedRevision.Value != strconv.FormatInt(d.Revision, 10) {
		return "", time.Time{}, errs.New(errs.ReasonRequestInvalid, "a release's confirmation names the disposition's revision (expected_revision)")
	}
	o, until := m.dispositionBinding(d)
	basis, who := basisHolding, confirmer
	switch in.Basis {
	case "", basisHolding:
		switch ok, err := m.confirmerEligible(ctx, tx, confirmer, false); {
		case err != nil:
			return "", time.Time{}, err
		case ok == unprovable:
			return "", time.Time{}, errs.New(errs.ReasonAuthorizationUnprovable, "the confirmer's eligibility cannot be proven now")
		case ok == disproven:
			return "", time.Time{}, errs.New(errs.ReasonPermissionDenied, "only another authorization admin confirms (A123)")
		}
	case basisOwner:
		at, err := time.Parse(time.RFC3339Nano, in.ExpiresAt)
		if err != nil || !at.After(time.Now()) || at.After(until.Add(time.Minute)) {
			return "", time.Time{}, errs.New(errs.ReasonRequestInvalid, "expires_at is an instant ahead, no later than a confirmation holds")
		}
		o.ExpiresAt = in.ExpiresAt
		key, err := m.ownerKey()
		if err != nil {
			return "", time.Time{}, err
		}
		if !o.Verify(key, in.Signature) {
			return "", time.Time{}, errs.New(errs.ReasonPermissionDenied, "the deployment owner's signature does not verify")
		}
		basis, who, until = basisOwner, ownerName, at
		m.rt.Logger.Error("the deployment owner's confirmation was used", "disposition", d.ID, "submitted_by", confirmer)
	default:
		return "", time.Time{}, errs.New(errs.ReasonRequestInvalid, "basis is holding or deployment_owner")
	}
	id := ids.New().String()
	_, err = tx.Exec(ctx, `INSERT INTO authz_confirmation (id, disposition, disposition_revision, confirmer, basis, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, id, d.ID, d.Revision, who, basis, until)
	return id, until, err
}

// releaseHTTP takes a release of the disposition in the path: 09a's disposition_release (its key, the disposition's
// revision, its confirmations).
func (m *Module) releaseHTTP(c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	var in struct {
		ChangeKey       string       `json:"change_key"`
		Revision        *revisionRef `json:"disposition_revision,omitempty"`
		SignalRefs      []string     `json:"signal_refs,omitempty"`
		ConfirmationIDs []string     `json:"confirmation_ids,omitempty"`
	}
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	ctx, _, err := s.Check(c.Ctx(), OpRelease, sdkauthz.Facts{})
	if err != nil {
		return err
	}
	u, _ := identity.UserFrom(ctx)
	res, err := m.change(ctx, u.Subject, request{ChangeKey: in.ChangeKey, Direction: "release", ConfirmationIDs: in.ConfirmationIDs,
		Release: &releaseIn{Disposition: c.Param("id"), Revision: in.Revision, SignalRefs: in.SignalRefs}})
	if err != nil {
		return err
	}
	return answer(c, res)
}
