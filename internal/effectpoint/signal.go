package effectpoint

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	"github.com/brickKit/be-sdk-go/v3/audit"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/jackc/pgx/v5"
)

// Identity-side dispositions (security 08, "身份侧处置的派生"; T6c): when this member applies an account status
// (an event, a pull, an alignment's snapshot) and the account turns from neither frozen nor marked to frozen, or to
// disabled with a compromised or suspicious mark, a disposition is made with no condition: the deployment's whole
// domain, the person's every segment, its effective records held. One active identity-side disposition per account:
// a further freeze or mark is merged into its signal_ref set and advances its revision (a release confirmed before
// no longer holds). An account seen the first time is no transition; a status applied again changes nothing; an
// unfreeze on the identity side does not release it.

// IdentitySignal is the Changed hook's part for dispositions, in the transaction that applied the account's status.
func IdentitySignal(m *core.Base, ctx context.Context, tx db.Tx, principal string) error {
	state, _, data, ok, err := m.Accounts.Get(ctx, tx, principal)
	if err != nil || !ok || state != "complete" {
		return err
	}
	var rec struct {
		Status   string `json:"status"`
		Mark     string `json:"security_mark"`
		Evidence string `json:"evidence"`
		Revision struct {
			Value string `json:"value"`
		} `json:"revision"`
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return err
	}
	marked := rec.Status == "security_frozen" || rec.Status == "disabled" && (rec.Mark == "compromised" || rec.Mark == "suspicious")
	// the signal is (the account, the evidence record that made the change: 09a's evidence), the same when the identity
	// member replays it in a full recovery; a record without it (an older identity member) by its revision
	ref := principal + "@" + rec.Revision.Value
	if rec.Evidence != "" {
		ref = principal + "@" + rec.Evidence
	}
	var was bool
	var last string
	err = tx.QueryRow(ctx, "SELECT marked, ref FROM authz_account_signal WHERE principal = $1 FOR UPDATE", principal).Scan(&was, &last)
	first := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !first {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO authz_account_signal (principal, marked, ref) VALUES ($1, $2, $3)
		ON CONFLICT (principal) DO UPDATE SET marked = excluded.marked, ref = excluded.ref, updated_at = now()`,
		principal, marked, ref); err != nil {
		return err
	}
	if first || !marked || ref == last { // first seen; not frozen or marked; the same status again
		return nil
	}
	if _, err := tx.Exec(ctx, "SELECT 1 FROM authz_state FOR UPDATE"); err != nil { // the effect point's guard
		return err
	}
	var active string
	err = tx.QueryRow(ctx, `SELECT id::text FROM authz_disposition WHERE state = 'active' AND origin = 'identity_side'
		AND $1 = ANY(accounts) FOR UPDATE`, principal).Scan(&active)
	switch {
	case err == nil: // a further freeze or mark: merged, the revision advanced
		_, err := tx.Exec(ctx, `UPDATE authz_disposition SET signal_ref = array_append(signal_ref, $2), revision = revision + 1,
			updated_at = now() WHERE id = $1 AND NOT ($2 = ANY(signal_ref))`, active, ref)
		return err
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}
	if was { // still frozen or marked, its disposition released since: no transition (security 08)
		return nil
	}
	return identityDisposition(m, ctx, tx, principal, ref)
}

// identityDisposition makes an identity-side disposition: the root's domain, the person's every segment, its
// effective records held.
func identityDisposition(m *core.Base, ctx context.Context, tx db.Tx, principal, ref string) error {
	id, held, err := GlobalDisposition(m, ctx, tx, principal, "identity_side", []string{ref}, core.ID+":identity_signal:"+ref)
	if err != nil || id == "" {
		return err
	}
	m.RT.Logger.Warn("an identity-side signal made a security disposition", "subject", principal, "disposition", id,
		"held", held)
	_, err = m.RT.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: core.OpDispose,
		Outcome: audit.Succeeded, Actor: core.ID, Target: map[string]any{"type": DispositionType, "id": id},
		Changes: map[string]any{"origin": "identity_side", "signal_ref": ref, "held": held}})
	return err
}

// GlobalDisposition makes a disposition of the deployment's whole domain (the root): the person's every segment,
// its effective records held, the security revision advanced. No root yet (before the install claim): nothing to
// hold, no disposition (id empty).
func GlobalDisposition(m *core.Base, ctx context.Context, tx db.Tx, principal, origin string, refs []string, change string) (
	id string, held int, err error) {
	units, err := Units(m, ctx, tx)
	if err != nil {
		return "", 0, err
	}
	root := ""
	for uid, u := range units {
		if u.Root && u.ID == uid {
			root = uid
		}
	}
	if root == "" {
		return "", 0, nil
	}
	recs, err := inScope(m, ctx, tx, units, dispositionIn{Subject: principal, All: true}, root)
	if err != nil {
		return "", 0, err
	}
	id = ids.New().String()
	if _, err := tx.Exec(ctx, `INSERT INTO authz_disposition (id, state, origin, subject, accounts, suspended_segments,
		all_scope, domain, signal_ref, change) VALUES ($1, 'active', $2, $3, $4, '[]', true, $5, $6, $7)`,
		id, origin, principal, []string{principal}, root, NonNil(refs), change); err != nil {
		return "", 0, err
	}
	for _, r := range recs {
		if _, err := Transition(m, ctx, tx, r, "held", "", "security_hold", change, ""); err != nil {
			return "", 0, err
		}
		if _, err := tx.Exec(ctx, "UPDATE authz_record SET disposition = $2 WHERE id = $1", r, id); err != nil {
			return "", 0, err
		}
	}
	return id, len(recs), core.Advance(ctx, tx)
}

// releaseSignals is a release's part for an identity-side disposition: it names the signal records to remove; while
// any is left the disposition stays active and nothing it holds comes back.
func releaseSignals(ctx context.Context, tx db.Tx, d *dispositionRow, remove []string) (left []string, ok bool, err error) {
	var set []string
	if err := tx.QueryRow(ctx, "SELECT signal_ref FROM authz_disposition WHERE id = $1", d.ID).Scan(&set); err != nil {
		return nil, false, err
	}
	if len(remove) == 0 {
		return nil, false, nil
	}
	for _, r := range remove {
		if !slices.Contains(set, r) {
			return nil, false, nil
		}
	}
	for _, s := range set {
		if !slices.Contains(remove, s) {
			left = append(left, s)
		}
	}
	return left, true, nil
}
