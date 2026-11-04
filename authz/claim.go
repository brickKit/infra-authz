package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
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

// The install claim (security 08, "安装认领"; T6g; A130): at installation, with no management yet, the member records
// a claim from AUTHZ_INSTALL_CLAIM — an exact platform principal (principal:<id>) or the digest of a one-time code
// (code:sha256:<hex>) — with its expiry, under this database's deployment recovery generation. The claimant, logged
// in, posts it (POST /api/authz/claim, with the code when it is one); in that transaction the claimant becomes the
// first authorization admin and the claim is consumed, once. A database restored from an older backup has advanced
// its generation: a claim of the old one is never open again.

// DefaultClaimValidity is how long an install claim stays open.
const DefaultClaimValidity = 7 * 24 * time.Hour

// parseClaim reads AUTHZ_INSTALL_CLAIM: kind and value.
func parseClaim(text string) (kind, value string, err error) {
	switch {
	case strings.HasPrefix(text, "principal:") && len(text) > len("principal:"):
		return "principal", strings.TrimPrefix(text, "principal:"), nil
	case strings.HasPrefix(text, "code:sha256:") && len(text) == len("code:sha256:")+64:
		v := strings.ToLower(strings.TrimPrefix(text, "code:sha256:"))
		if _, err := hex.DecodeString(v); err == nil {
			return "code", v, nil
		}
	}
	return "", "", errors.New("AUTHZ_INSTALL_CLAIM is principal:<platform principal> or code:sha256:<64 hex digits>")
}

// recordClaim records the install claim at installation (no management yet), under this database's generation.
func (m *Module) recordClaim(ctx context.Context, tx db.Tx) error {
	text := m.rt.Config.Secret("AUTHZ_INSTALL_CLAIM").Value()
	if text == "" {
		return nil
	}
	kind, value, err := parseClaim(text)
	if err != nil {
		return errs.New(errs.ReasonRequestInvalid, err.Error())
	}
	_, err = tx.Exec(ctx, `INSERT INTO authz_claim (generation, kind, value, expires_at)
		SELECT generation, $1, $2, now() + $3::interval FROM be_current_db_epoch() ON CONFLICT DO NOTHING`,
		kind, value, m.rt.Config.Duration("AUTHZ_INSTALL_CLAIM_VALIDITY").String())
	return err
}

// claimHTTP consumes the install claim: the caller is its principal, or presents its code.
func (m *Module) claimHTTP(c *httpx.Context) error {
	var in struct {
		Code string `json:"code,omitempty"`
	}
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	u, _ := identity.UserFrom(c.Ctx())
	refused := errs.New(errs.ReasonPermissionDenied, "no open install claim for this caller")
	err := m.rt.DB.Tx(c.Ctx(), func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT 1 FROM authz_state FOR UPDATE"); err != nil { // the effect point's guard
			return err
		}
		var kind, value string
		var open bool
		err := tx.QueryRow(ctx, `SELECT c.kind, c.value, c.consumed_by IS NULL AND c.expires_at > now()
			FROM authz_claim c, be_current_db_epoch() e WHERE c.generation = e.generation FOR UPDATE OF c`).Scan(&kind, &value, &open)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !open {
			return refused
		}
		if err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(in.Code))
		if kind == "principal" && value != u.Subject || kind == "code" && (in.Code == "" || hex.EncodeToString(sum[:]) != value) {
			return refused
		}
		var holdings int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM authz_record WHERE record_type = 'management_holding'").Scan(&holdings); err != nil {
			return err
		}
		if holdings > 0 {
			return refused
		}
		if err := m.claim(ctx, tx, u.Subject); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE authz_claim c SET consumed_by = $1, consumed_at = now() FROM be_current_db_epoch() e
			WHERE c.generation = e.generation`, u.Subject)
		return err
	})
	if err != nil {
		return err
	}
	return c.JSON(200, map[string]any{"claimed": u.Subject})
}

// claim makes holder the first authorization admin over a root unit, with a manager's grant on the security records
// and the dispositions.
func (m *Module) claim(ctx context.Context, tx db.Tx, holder string) error {
	root, holding, grant := ids.New().String(), ids.New().String(), ids.New().String()
	from := canon.Time(time.Now().Add(-time.Minute))
	seg := func(op string) sdkauthz.Segment {
		return sdkauthz.Segment{ResourceType: Records, Operation: op, Atoms: map[string]sdkauthz.Atom{Holder: {Kind: "all"}},
			ReadFields: []string{"body", "id", "record_type", "state"}, Valid: sdkauthz.Window{From: from}}
	}
	disp := func(op string) sdkauthz.Segment { // the dispositions (A128): no dimensions
		return sdkauthz.Segment{ResourceType: Dispositions, Operation: op, Atoms: map[string]sdkauthz.Atom{},
			ReadFields: []string{"body", "id"}, Valid: sdkauthz.Window{From: from}}
	}
	write := func(id, typ string, body any) error {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO authz_record (id, record_type, state, body, requested_by) VALUES ($1, $2, 'active', $3, $4)`,
			id, typ, b, ID); err != nil {
			return err
		}
		return indexSources(ctx, tx, id, typ, b)
	}
	for _, w := range []struct {
		id, typ string
		body    any
	}{
		{root, "management_unit", unitBody{Name: "deployment", Root: true}},
		{holding, "management_holding", holdingBody{Unit: root, Holder: holder, SystemRole: "authorization_admin"}},
		{grant, "grant", grantBody{Grantee: holder, Segments: []sdkauthz.Segment{seg(OpRead), seg(OpChange), seg(OpTighten),
			disp(OpDispRead), disp(OpDispose), disp(OpRelease)},
			GovernanceUnit: root, IssuedBy: ID}},
	} {
		if err := write(w.id, w.typ, w.body); err != nil {
			return err
		}
	}
	if err := advance(ctx, tx); err != nil {
		return err
	}
	m.rt.Logger.Warn("install claim: the claimant is the first authorization admin", "principal", holder)
	_, err := m.rt.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: OpChange,
		Outcome: audit.Succeeded, Actor: ID, Target: map[string]any{"type": "management_holding", "id": holding},
		Changes: map[string]any{"action": "install_claim", "holder": holder}})
	return err
}
