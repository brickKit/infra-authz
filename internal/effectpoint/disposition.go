package effectpoint

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/identity"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/jackc/pgx/v5"
)

// Security dispositions (security 08, "安全处置"; 09a's be.security.security_disposition; A128): a disposition
// suspends a natural person's access within a scope of a governance domain. Its records in that scope are held
// (security_hold) when it is made, and while it is active every segment of the person that meets the suspended scope
// is left out of the views whole: whatever the segment comes from, a new grant, a renewal or a relinquish segment,
// there is no way around it. "Meets" is conservative: only a scope provably disjoint lets a segment through.

// disposition is an active disposition as evaluation sees it.
type disposition struct {
	ID, Subject, Domain string
	All                 bool // the person's every segment (identity-side dispositions)
	Segments            []sdkauthz.Segment
}

// ActiveDispositions are the active dispositions by subject.
func ActiveDispositions(ctx context.Context, tx db.Tx) (map[string][]disposition, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, subject, domain::text, all_scope, suspended_segments
		FROM authz_disposition WHERE state = 'active'`)
	if err != nil {
		return nil, err
	}
	ds, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (disposition, error) {
		var d disposition
		var raw []byte
		if err := r.Scan(&d.ID, &d.Subject, &d.Domain, &d.All, &raw); err != nil {
			return d, err
		}
		return d, json.Unmarshal(raw, &d.Segments)
	})
	if err != nil {
		return nil, err
	}
	out := map[string][]disposition{}
	for _, d := range ds {
		out[d.Subject] = append(out[d.Subject], d)
	}
	return out, nil
}

// Suspended: s, a segment of subject, meets a scope one of its active dispositions suspends.
func Suspended(ds []disposition, s sdkauthz.Segment, subject string) bool {
	for _, d := range ds {
		if d.All {
			return true
		}
		for _, scope := range d.Segments {
			if !disjoint(s, scope, subject) {
				return true
			}
		}
	}
	return false
}

// disjoint: a and b provably have no row and instant in common: another resource type or operation, a dimension whose
// atoms provably share nothing (security 07's table), or validities that do not overlap. A pair outside the table is
// not provably disjoint: it meets.
func disjoint(a, b sdkauthz.Segment, subject string) bool {
	if a.ResourceType != b.ResourceType || a.Operation != b.Operation {
		return true
	}
	if _, ok := core.WindowIntersect(a.Valid, b.Valid); !ok {
		return true
	}
	for dim, x := range a.Atoms {
		if y, ok := b.Atoms[dim]; ok && atomsDisjoint(x, y, subject) {
			return true
		}
	}
	return false
}

// atomsDisjoint: two atoms of one dimension provably share no value. Only pairs in security 07's table can be; all
// meets everything.
func atomsDisjoint(x, y sdkauthz.Atom, subject string) bool {
	switch {
	case x.Kind == "all" || y.Kind == "all":
		return false
	case x.Kind == "in" && y.Kind == "in":
		return !slices.ContainsFunc(x.Values, func(v string) bool { return slices.Contains(y.Values, v) })
	case x.Kind == "self" && y.Kind == "in":
		return !slices.Contains(y.Values, subject)
	case x.Kind == "in" && y.Kind == "self":
		return !slices.Contains(x.Values, subject)
	case x.Kind == "tree" && y.Kind == "tree":
		for _, a := range x.Items {
			for _, b := range y.Items {
				if core.Covers(a, b) || core.Covers(b, a) {
					return false
				}
			}
		}
		return true
	case x.Kind == "interval" && y.Kind == "interval":
		if x.Currency != y.Currency {
			return true // a row has one currency
		}
		z := x
		z.Lo, z.LoClosed = core.TighterBound(x.Lo, x.LoClosed, y.Lo, y.LoClosed, -1)
		z.Hi, z.HiClosed = core.TighterBound(x.Hi, x.HiClosed, y.Hi, y.HiClosed, 1)
		if z.Lo == nil || z.Hi == nil {
			return false
		}
		cmp, ok := core.DecimalCompare(*z.Lo, *z.Hi)
		return ok && (cmp > 0 || cmp == 0 && !(core.IsClosed(z.LoClosed) && core.IsClosed(z.HiClosed)))
	}
	return false
}

// dispositionIn is a disposition as its requester submits it, the candidate of a tightening without a target
// (POST /api/authz/dispositions): whom, in which governance domain (a unit; the root when empty), and what scope —
// segments within the domain's limit, or the person's every segment (all, the root's domain only).
type dispositionIn struct {
	RecordType        string             `json:"record_type"`
	Subject           string             `json:"subject"`
	Domain            string             `json:"domain,omitempty"`
	SuspendedSegments []sdkauthz.Segment `json:"suspended_segments,omitempty"`
	All               bool               `json:"all_scope,omitempty"`
}

const DispositionType = "security_disposition"

// plannedDisposition is what a disposition writes when it applies: the record, and the person's records it holds.
type plannedDisposition struct {
	in      dispositionIn
	domain  string
	records []string
}

// disposing reads a new disposition (A128): the requester manages the domain; the scope is within the domain's limit;
// the person's grants governed in the domain or below that meet the scope, and its management holdings there, are to
// be held. Disposing another authorization admin is a protected tightening (row 21); a disposition is never held
// back by the last-admin invariant (rows 27-28).
func disposing(m *core.Base, ctx context.Context, tx db.Tx, e Entry, s Standing, f *core.Facts, p *plan) (bool, *ChangeResult, error) {
	f.Kind, f.Disposition = core.Tighten, true
	var in dispositionIn
	if err := json.Unmarshal(e.Req.Candidate, &in); err != nil || in.Subject == "" {
		return false, invalid("a disposition names its subject"), nil
	}
	root := ""
	for id, u := range s.units {
		if u.Root && u.ID == id {
			root = id
		}
	}
	domain := in.Domain
	if domain == "" {
		domain = root
	}
	lim := s.Limits.Of(domain)
	if lim == nil {
		return false, invalid("no active unit " + domain), nil
	}
	switch {
	case in.All && !sameUnit(s.units, domain, root):
		return false, invalid("a disposition of the person's every segment is the root's: a domain below suspends segments within its limit"), nil
	case !in.All && len(in.SuspendedSegments) == 0:
		return false, invalid("a disposition suspends segments, or the person's every segment (all_scope)"), nil
	}
	if !in.All {
		why, err := contains(m, ctx, tx, in.SuspendedSegments, s.Limits.OfFor(domain, in.Subject), in.Subject)
		if err != nil {
			var rej *ChangeResult
			if errors.As(err, &rej) {
				return false, rej, nil
			}
			return false, nil, err
		}
		if why != "" {
			return false, &ChangeResult{Outcome: "rejected", Reason: errs.ReasonContainmentNotProven, Detail: why}, nil
		}
	}
	held, err := inScope(m, ctx, tx, s.units, in, domain)
	if err != nil {
		return false, nil, err
	}
	p.disp, p.recType = &plannedDisposition{in: in, domain: domain, records: held}, DispositionType
	// the person an authorization admin: protected unless it is the requester itself; confirmations bind its admin
	// holding at its revision
	admins, err := AdminHoldingsOf(ctx, tx, in.Subject)
	if err != nil {
		return false, nil, err
	}
	if len(admins) > 0 {
		f.AffectsAdmins, f.TightenNeedsConfirmation = true, in.Subject != e.Requester
		t, err := LockTarget(ctx, tx, admins[0])
		if err != nil {
			return false, nil, err
		}
		if p.confirmed, err = confirmationsOf(m, ctx, tx, e.Req.ConfirmationIDs, t, e.Requester, in.Subject, false, f); err != nil {
			return false, nil, err
		}
	}
	return s.manages(domain), nil, nil
}

// AdminHoldingsOf are a principal's active authorization admin holdings.
func AdminHoldingsOf(ctx context.Context, tx db.Tx, principal string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT id::text FROM authz_record WHERE state = 'active' AND record_type = 'management_holding'
		AND body->>'holder' = $1 AND body->>'system_role' = 'authorization_admin' ORDER BY created_at, id`, principal)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// inScope are the person's active records a disposition holds: grants governed in the domain or below whose
// segments meet the scope (all: every one), and its management holdings in the domain or below.
func inScope(m *core.Base, ctx context.Context, tx db.Tx, units map[string]core.UnitBody, in dispositionIn, domain string) ([]string, error) {
	recs, err := core.Active(ctx, tx, "grant", "management_holding")
	if err != nil {
		return nil, err
	}
	under := func(u string) bool {
		for range len(units) + 1 {
			if sameUnit(units, u, domain) {
				return true
			}
			if u = units[u].Parent; u == "" {
				return false
			}
		}
		return false
	}
	scope := []disposition{{All: in.All, Segments: in.SuspendedSegments}}
	var out []string
	for _, r := range recs {
		switch r.Type {
		case "grant":
			var b core.GrantBody
			if err := json.Unmarshal(r.Body, &b); err != nil {
				return nil, err
			}
			segs := b.Segments
			if b.RoleRevision != "" {
				if segs, err = RoleTemplate(ctx, tx, b.RoleRevision); err != nil {
					return nil, err
				}
			}
			if b.Grantee != in.Subject || !under(b.GovernanceUnit) {
				continue
			}
			if slices.ContainsFunc(segs, func(sg sdkauthz.Segment) bool { return Suspended(scope, sg, in.Subject) }) {
				out = append(out, r.ID)
			}
		case "management_holding":
			var h core.HoldingBody
			if err := json.Unmarshal(r.Body, &h); err != nil {
				return nil, err
			}
			if h.Holder == in.Subject && under(h.Unit) {
				out = append(out, r.ID)
			}
		}
	}
	return out, nil
}

// IsDisposition: a candidate is a security disposition.
func IsDisposition(candidate json.RawMessage) bool {
	var head struct {
		RecordType string `json:"record_type"`
	}
	return len(candidate) > 0 && json.Unmarshal(candidate, &head) == nil && head.RecordType == DispositionType
}

// dispose writes a disposition that applied: the record, and the person's records in its scope held (security_hold)
// by it; the security revision advances (the views leave the suspended segments out) and the audit says so.
func dispose(m *core.Base, ctx context.Context, tx db.Tx, e Entry, p plan, change string) (ChangeResult, error) {
	d := p.disp
	id := ids.New().String()
	segs := d.in.SuspendedSegments
	if segs == nil {
		segs = []sdkauthz.Segment{}
	}
	raw, err := json.Marshal(segs)
	if err != nil {
		return ChangeResult{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO authz_disposition (id, state, origin, subject, accounts, suspended_segments,
		all_scope, domain, disposer, confirmations, change) VALUES ($1, 'active', 'admin', $2, $3, $4, $5, $6, $7, $8, $9)`,
		id, d.in.Subject, []string{d.in.Subject}, raw, d.in.All, d.domain, e.Requester, NonNil(p.confirmed), change); err != nil {
		return ChangeResult{}, err
	}
	for _, r := range d.records {
		if _, err := Transition(m, ctx, tx, r, "held", "", "security_hold", change, ""); err != nil {
			return ChangeResult{}, err
		}
		if _, err := tx.Exec(ctx, "UPDATE authz_record SET disposition = $2 WHERE id = $1", r, id); err != nil {
			return ChangeResult{}, err
		}
	}
	if err := useConfirmations(ctx, tx, p.confirmed, change); err != nil {
		return ChangeResult{}, err
	}
	rev, err := applied(m, ctx, tx, e.operation(), e.Requester, core.Tighten, DispositionType, id, p.basis)
	if err != nil {
		return ChangeResult{}, err
	}
	res := ChangeResult{Outcome: "applied", Record: id, NewRevision: &RevisionRef{Domain: DispositionDomain, Value: "1"},
		SecurityRevisions: []RevisionRef{{Domain: core.SecurityDomain, Value: strconv.FormatInt(rev, 10)}}}
	if p.basis != nil {
		res.Basis = "last_applied"
	}
	return res, nil
}

// dispositionDomain numbers a disposition's revisions.
const DispositionDomain = "authz.disposition.revision"

func NonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// DisposeHTTP takes a disposition: be.security.change_request's key and confirmations, the disposition as its
// candidate (dispositionIn). It enters the effect point as a tightening without a target.
func DisposeHTTP(m *core.Base, c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	var in struct {
		dispositionIn
		ChangeKey       string   `json:"change_key"`
		ConfirmationIDs []string `json:"confirmation_ids,omitempty"`
	}
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	in.RecordType = DispositionType
	candidate, err := json.Marshal(in.dispositionIn)
	if err != nil {
		return err
	}
	ctx, _, err := s.Check(c.Ctx(), core.OpDispose, sdkauthz.Facts{})
	if err != nil {
		return err
	}
	u, _ := identity.UserFrom(ctx)
	res, err := change(m, ctx, u.Subject, Request{ChangeKey: in.ChangeKey, Direction: core.Tighten, Candidate: candidate,
		ConfirmationIDs: in.ConfirmationIDs})
	if err != nil {
		return err
	}
	return answer(c, res)
}

// DispositionsHTTP lists the dispositions, newest first.
func DispositionsHTTP(m *core.Base, c *httpx.Context) error {
	s, _ := sdkauthz.From(c.Ctx())
	ctx, _, err := s.Check(c.Ctx(), core.OpDispRead, sdkauthz.Facts{})
	if err != nil {
		return err
	}
	var out []map[string]any
	err = m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, json_build_object('state', state, 'origin', origin, 'subject', subject,
			'accounts', accounts, 'suspended_segments', suspended_segments, 'all_scope', all_scope, 'domain', domain,
			'disposer', disposer, 'signal_ref', signal_ref, 'revision', revision::text, 'released_by', released_by)
			FROM authz_disposition ORDER BY created_at DESC, id`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (map[string]any, error) {
			var id string
			var body json.RawMessage
			err := r.Scan(&id, &body)
			return map[string]any{"id": id, "body": body}, err
		})
		return err
	})
	if err != nil {
		return err
	}
	return c.JSON(200, map[string]any{"dispositions": out})
}
