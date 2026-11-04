//go:build integration

package authz

import (
	"context"
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
	recoveryPriv ed25519.PrivateKey
	ownerPriv    ed25519.PrivateKey
	itAdmin      *pgx.Conn
)

// recoveryPublicPEM is the test deployment's recovery key (A129), another pair than the owner's.
func recoveryPublicPEM(t *testing.T) string {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	recoveryPriv = priv
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

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

// protectBy is protect with another authorization admin's confirmation: while one is available, the owner's key does
// not stand in for an independent person on a widening.
func protectBy(t *testing.T, w *sectest.World, who, confirmer string, req map[string]any) map[string]any {
	t.Helper()
	out := submitChange(t, w, who, req, 202)
	require.Equal(t, "awaiting_confirmation", out["outcome"], "%v", out)
	code, c := call(t, w, confirmer, "POST", "/api/authz/confirmations", map[string]any{"target": out["record"]})
	require.Equal(t, 201, code, "%v", c)
	require.Eventually(t, func() bool { return recordOf(t, itAdmin, out["record"]).State == "active" }, 10*time.Second,
		50*time.Millisecond, "confirmed: the member's job applies it")
	return map[string]any{"record": out["record"], "outcome": "applied"}
}

// ownerConfirmRelease confirms a disposition's release with the deployment owner's key, bound to the disposition at
// revision 1.
func ownerConfirmRelease(t *testing.T, w *sectest.World, id string) map[string]any {
	t.Helper()
	code, p := call(t, w, sectest.Alice, "GET", "/api/authz/confirmations/owner-payload?disposition="+url.QueryEscape(id), nil)
	require.Equal(t, 200, code, "%v", p)
	str := func(k string) string { v, _ := p[k].(string); return v }
	o := sdkauthz.OwnerConfirmation{Deployment: str("deployment"), Target: str("target"), ExpectedRevision: str("expected_revision"),
		ExpiresAt: str("expires_at")}
	sig, err := o.Sign(ownerPriv)
	require.NoError(t, err)
	code, c := call(t, w, sectest.Alice, "POST", "/api/authz/confirmations", map[string]any{"disposition": id,
		"expected_revision": map[string]any{"domain": dispositionDomain, "value": o.ExpectedRevision}, "basis": "deployment_owner",
		"expires_at": o.ExpiresAt, "signature": sig})
	require.Equal(t, 201, code, "%v", c)
	return c
}

// releaseIdentitySide releases who's active identity-side disposition (all its signals), the owner confirming it when
// who is an authorization admin.
func releaseIdentitySide(t *testing.T, w *sectest.World, who, key string) {
	t.Helper()
	var id string
	var rev int64
	var refs []string
	require.NoError(t, itAdmin.QueryRow(context.Background(), "SELECT id::text, revision, signal_ref FROM "+itSchema+
		".authz_disposition WHERE subject = $1 AND origin = 'identity_side' AND state = 'active'", who).Scan(&id, &rev, &refs))
	body := map[string]any{"change_key": key, "signal_refs": refs,
		"disposition_revision": map[string]any{"domain": dispositionDomain, "value": itoa64(rev)}}
	code, out := call(t, w, sectest.Alice, "POST", "/api/authz/dispositions/"+id+"/release", body)
	if code == 202 && out["outcome"] == "awaiting_confirmation" {
		body["confirmation_ids"] = []any{ownerConfirmRelease(t, w, id)["id"]}
		code, out = call(t, w, sectest.Alice, "POST", "/api/authz/dispositions/"+id+"/release", body)
	}
	require.Equal(t, 200, code, "%v", out)
}
