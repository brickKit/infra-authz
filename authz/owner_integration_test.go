//go:build integration

package authz

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"testing"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// The test deployment's owner key (A124): generated per run, its public key in the member's configuration; and the
// database connection the helpers read records with.
var (
	ownerPriv ed25519.PrivateKey
	itAdmin   *pgx.Conn
)

func ownerPublicPEM(t *testing.T) string {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ownerPriv = priv
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// ownerConfirm confirms target with the deployment owner's key: what to sign comes from the member, the signature
// from the key; revision is a tightening's content revision ("" for a saved widening).
func ownerConfirm(t *testing.T, w *sectest.World, who string, target any, revision string) map[string]any {
	t.Helper()
	q := "/api/authz/confirmations/owner-payload?target=" + url.QueryEscape(target.(string))
	if revision != "" {
		q += "&expected_revision=" + revision
	}
	code, p := call(t, w, who, "GET", q, nil)
	require.Equal(t, 200, code, "%v", p)
	str := func(k string) string { v, _ := p[k].(string); return v }
	o := sdkauthz.OwnerConfirmation{Deployment: str("deployment"), Target: str("target"), CandidateDigest: str("candidate_digest"),
		ExpectedRevision: str("expected_revision"), ExpiresAt: str("expires_at")}
	sig, err := o.Sign(ownerPriv)
	require.NoError(t, err)
	body := map[string]any{"target": target, "basis": "deployment_owner", "expires_at": o.ExpiresAt, "signature": sig}
	if revision != "" {
		body["expected_revision"] = map[string]any{"domain": "authz.record.revision", "value": revision}
	}
	code, out := call(t, w, who, "POST", "/api/authz/confirmations", body)
	require.Equal(t, 201, code, "%v", out)
	return out
}

// protect submits a protected widening (a management unit or holding, security 08): saved awaiting confirmation,
// confirmed with the owner's key (no other authorization admin is available), applied by the member's job.
func protect(t *testing.T, w *sectest.World, who string, req map[string]any) map[string]any {
	t.Helper()
	out := submitChange(t, w, who, req, 202)
	require.Equal(t, "awaiting_confirmation", out["outcome"], "%v", out)
	ownerConfirm(t, w, who, out["record"], "")
	require.Eventually(t, func() bool { return recordOf(t, itAdmin, out["record"]).State == "active" }, 10*time.Second,
		50*time.Millisecond, "confirmed: the member's job applies it")
	return map[string]any{"record": out["record"], "outcome": "applied"}
}
