package adminrecovery

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	core "github.com/brickKit/infra-authz/v3/internal/core"
	effectpoint "github.com/brickKit/infra-authz/v3/internal/effectpoint"
	plans "github.com/brickKit/infra-authz/v3/internal/plans"

	"github.com/brickKit/be-sdk-go/v3/audit"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Administrator recovery (security 08, "管理员恢复"; T6f; A129): the deployment owner runs the recovery command on the
// deployment machine with the offline recovery key (cmd/recover); the member checks the signature, the deployment, the
// expiry and a nonce used once — no token, since no admin may be left to hold one. Three actions:
//   - replace (tightening 1-2): the named admin holdings are held, each as a disposition by the deployment owner of
//     its holder's every segment; the holder's unused confirmations are void and its pending widenings cancelled.
//     It needs no new generation;
//   - restore (widening 1-5): a new authorization recovery generation (views answer with it, components drop the old
//     ones); the deployment in administrator recovery; the identity's dispositions from the identity side or by a
//     replaced admin released; an admin holding made for it when it has no active one; told (audit and an error-level
//     log). Back to operational once the identity is provably available — now, or when its account status changes;
//   - abort: back to the state before the recovery; the generation advanced stays.
// The generation is the member's own counter in this version; the evidence store's (item 4) replaces it.

// RecoveryRequest is what the deployment owner signs.
type RecoveryRequest struct {
	Deployment string   `json:"deployment"`
	Action     string   `json:"action"` // replace, restore, abort
	Holdings   []string `json:"holdings,omitempty"`
	Identity   string   `json:"identity,omitempty"`
	Nonce      string   `json:"nonce"`
	ExpiresAt  string   `json:"expires_at"`
}

// Digest is the request's canonical digest under be.security.admin_recovery, what the signature covers.
func (r RecoveryRequest) Digest() (string, error) {
	v := map[string]any{"deployment": r.Deployment, "action": r.Action, "nonce": r.Nonce, "expires_at": r.ExpiresAt}
	if len(r.Holdings) > 0 {
		hs := make([]any, len(r.Holdings))
		for i, h := range r.Holdings {
			hs[i] = h
		}
		v["holdings"] = hs
	}
	if r.Identity != "" {
		v["identity"] = r.Identity
	}
	return canon.Digest("be.security.admin_recovery", 1, v)
}

// Sign signs the request's digest with the recovery key (base64).
func (r RecoveryRequest) Sign(key ed25519.PrivateKey) (string, error) {
	d, err := r.Digest()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(d))), nil
}

// MaxRecoveryValidity bounds how far ahead a recovery request may expire.
const MaxRecoveryValidity = time.Hour

// RecoveryHTTP takes a signed recovery request (a public route: the signature is the credential).
func RecoveryHTTP(m *core.Base, c *httpx.Context) error {
	var in struct {
		Request   RecoveryRequest `json:"request"`
		Signature string          `json:"signature"`
	}
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	r := in.Request
	key, err := effectpoint.PublicKey(m, "AUTHZ_RECOVERY_KEY")
	if err != nil {
		return err
	}
	d, err := r.Digest()
	if err != nil {
		return errs.New(errs.ReasonRequestInvalid, err.Error())
	}
	sig, err := base64.StdEncoding.DecodeString(in.Signature)
	if err != nil || !ed25519.Verify(key, []byte(d), sig) {
		return errs.New(errs.ReasonPermissionDenied, "the recovery signature does not verify")
	}
	at, err := time.Parse(time.RFC3339Nano, r.ExpiresAt)
	switch {
	case r.Deployment != m.Deployment:
		return errs.New(errs.ReasonPermissionDenied, "a recovery request of another deployment")
	case err != nil || !at.After(time.Now()) || at.After(time.Now().Add(MaxRecoveryValidity+time.Minute)):
		return errs.New(errs.ReasonRequestInvalid, "expires_at is an instant ahead, within an hour")
	case r.Nonce == "":
		return errs.New(errs.ReasonRequestInvalid, "a recovery request carries a nonce")
	}
	out := map[string]any{}
	err = m.RT.DB.Tx(c.Ctx(), func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO authz_recovery_nonce (nonce, action) VALUES ($1, $2)", r.Nonce, r.Action); err != nil {
			var pg *pgconn.PgError
			if errors.As(err, &pg) && pg.Code == "23505" {
				return errs.New(errs.ReasonPermissionDenied, "this recovery request was used already")
			}
			return err
		}
		if _, err := tx.Exec(ctx, "SELECT 1 FROM authz_state FOR UPDATE"); err != nil { // the effect point's guard
			return err
		}
		var err error
		switch r.Action {
		case "replace":
			err = recoveryReplace(m, ctx, tx, r)
		case "restore":
			err = recoveryRestore(m, ctx, tx, r)
		case "abort":
			err = recoveryAbort(m, ctx, tx)
		default:
			return errs.New(errs.ReasonRequestInvalid, "a recovery action is replace, restore or abort")
		}
		return err
	})
	if err != nil {
		return err
	}
	return m.RT.DB.Tx(c.Ctx(), func(ctx context.Context, tx db.Tx) error {
		var state string
		var gen int64
		if err := tx.QueryRow(ctx, "SELECT admin_state, recovery_generation FROM authz_state").Scan(&state, &gen); err != nil {
			return err
		}
		out["admin_state"], out["recovery_generation"] = state, gen
		return c.JSON(200, out)
	})
}

// recoveryReplace is the tightening part: each named admin holding held by a disposition of its holder by the owner.
func recoveryReplace(m *core.Base, ctx context.Context, tx db.Tx, r RecoveryRequest) error {
	if len(r.Holdings) == 0 {
		return errs.New(errs.ReasonRequestInvalid, "replace names the admin holdings to replace")
	}
	units, err := effectpoint.Units(m, ctx, tx)
	if err != nil {
		return err
	}
	root := rootOf(units)
	change := effectpoint.OwnerName + ":recovery:" + r.Nonce
	for _, id := range r.Holdings {
		t, err := effectpoint.LockTarget(ctx, tx, id)
		if err != nil {
			return err
		}
		var h core.HoldingBody
		if t != nil {
			_ = json.Unmarshal(t.Body, &h)
		}
		if t == nil || t.Type != "management_holding" || h.SystemRole != "authorization_admin" || t.State == "ended" {
			return errs.New(errs.ReasonRequestInvalid, "not an authorization admin holding: "+id)
		}
		disp := ids.New().String()
		if _, err := tx.Exec(ctx, `INSERT INTO authz_disposition (id, state, origin, subject, accounts, suspended_segments,
			all_scope, domain, disposer, change) VALUES ($1, 'active', 'admin_recovery', $2, $3, '[]', true, $4, $5, $6)`,
			disp, h.Holder, []string{h.Holder}, root, effectpoint.OwnerName, change); err != nil {
			return err
		}
		if _, err := effectpoint.Transition(m, ctx, tx, id, "held", "", "security_hold", change, ""); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE authz_record SET disposition = $2 WHERE id = $1", id, disp); err != nil {
			return err
		}
		// its unused confirmations are void; the plans it initiated or confirmed leave their pending items for review
		// (CP76); the widenings it asked for and not yet effective are cancelled
		if err := plans.ReviewReplaced(ctx, tx, h.Holder); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE authz_confirmation SET expires_at = now() WHERE confirmer = $1
			AND consumed_by_change IS NULL AND expires_at > now()`, h.Holder); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id::text FROM authz_record WHERE requested_by = $1
			AND state IN ('requested', 'awaiting_confirmation', 'scheduled')`, h.Holder)
		if err != nil {
			return err
		}
		pending, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		for _, p := range pending {
			if _, err := effectpoint.Transition(m, ctx, tx, p, "ended", "cancelled", "", change, ""); err != nil {
				return err
			}
		}
	}
	if err := core.Advance(ctx, tx); err != nil {
		return err
	}
	m.RT.Logger.Error("administrator recovery: authorization admin holdings replaced", "holdings", r.Holdings)
	if _, err := m.RT.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: core.OpChange,
		Outcome: audit.Succeeded, Actor: effectpoint.OwnerName, Target: map[string]any{"type": "admin_recovery"},
		Changes: map[string]any{"action": "replace", "holdings": r.Holdings}}); err != nil {
		return err
	}
	return effectpoint.JudgeAdmins(m, ctx, tx)
}

// recoveryRestore is the widening part: a new generation, administrator recovery, the identity's dispositions from
// the identity side or by a replaced admin released, an admin holding for it when it has none, told; operational when
// the identity is provably available.
func recoveryRestore(m *core.Base, ctx context.Context, tx db.Tx, r RecoveryRequest) error {
	if r.Identity == "" {
		return errs.New(errs.ReasonRequestInvalid, "restore names the identity to restore")
	}
	change := effectpoint.OwnerName + ":recovery:" + r.Nonce
	if _, err := tx.Exec(ctx, `UPDATE authz_state SET recovery_generation = recovery_generation + 1,
		entered_from = CASE WHEN admin_state = 'admin_recovery' THEN entered_from ELSE admin_state END,
		admin_state = 'admin_recovery', admin_state_since = now(), recovery_identity = $1`, r.Identity); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT d.id::text FROM authz_disposition d WHERE d.state = 'active' AND d.subject = $1
		AND (d.origin IN ('identity_side', 'recovery_review') OR d.disposer IN (SELECT subject FROM authz_disposition WHERE origin = 'admin_recovery'
			AND state = 'active'))`, r.Identity)
	if err != nil {
		return err
	}
	disps, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, d := range disps {
		rows, err := tx.Query(ctx, `SELECT id::text FROM authz_record WHERE disposition = $1 AND state = 'held'
			AND hold_reason = 'security_hold'`, d)
		if err != nil {
			return err
		}
		held, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		if err := effectpoint.ReleaseDisposition(m, ctx, tx, d, held, effectpoint.OwnerName, change); err != nil {
			return err
		}
	}
	admins, err := effectpoint.AdminHoldingsOf(ctx, tx, r.Identity)
	if err != nil {
		return err
	}
	if len(admins) == 0 {
		units, err := effectpoint.Units(m, ctx, tx)
		if err != nil {
			return err
		}
		body, _ := json.Marshal(core.HoldingBody{Unit: rootOf(units), Holder: r.Identity, SystemRole: "authorization_admin"})
		id := ids.New().String()
		if _, err := tx.Exec(ctx, `INSERT INTO authz_record (id, record_type, state, body, requested_by, last_change)
			VALUES ($1, 'management_holding', 'active', $2, $3, $4)`, id, body, effectpoint.OwnerName, change); err != nil {
			return err
		}
		if err := effectpoint.IndexSources(ctx, tx, id, "management_holding", body); err != nil {
			return err
		}
	}
	if err := core.Advance(ctx, tx); err != nil {
		return err
	}
	m.RT.Logger.Error("administrator recovery: an authorization admin restored; review it, and rotate the recovery key",
		"identity", r.Identity, "released_dispositions", len(disps))
	if _, err := m.RT.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: core.OpChange,
		Outcome: audit.Succeeded, Actor: effectpoint.OwnerName, Target: map[string]any{"type": "admin_recovery"},
		Changes: map[string]any{"action": "restore", "identity": r.Identity, "released_dispositions": disps}}); err != nil {
		return err
	}
	return effectpoint.JudgeAdmins(m, ctx, tx)
}

// recoveryAbort goes back to the state before the recovery (the generation advanced stays).
func recoveryAbort(m *core.Base, ctx context.Context, tx db.Tx) error {
	tag, err := tx.Exec(ctx, `UPDATE authz_state SET admin_state = coalesce(entered_from, 'recovery_pending'),
		entered_from = NULL, recovery_identity = NULL, admin_state_since = now() WHERE admin_state = 'admin_recovery'`)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errs.New(errs.ReasonRequestInvalid, "no administrator recovery to abort")
	}
	_, err = m.RT.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: core.OpChange,
		Outcome: audit.Succeeded, Actor: effectpoint.OwnerName, Target: map[string]any{"type": "admin_recovery"},
		Changes: map[string]any{"action": "abort"}})
	return err
}

// rootOf is the root management unit's record.
func rootOf(units map[string]core.UnitBody) string {
	for id, u := range units {
		if u.Root && u.ID == id {
			return id
		}
	}
	return ""
}
