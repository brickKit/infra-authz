package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeygenThenSignVerifies(t *testing.T) {
	dir := t.TempDir()
	key, pub := filepath.Join(dir, "owner.key.pem"), filepath.Join(dir, "owner.pub.pem")
	require.NoError(t, run(true, key, pub, nil, nil))
	st, err := os.Stat(key)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm(), "the private key is the owner's alone")

	payload := `{"deployment":"dep-1","target":"rec-1","candidate_digest":"sha256:c","expires_at":"2026-11-05T00:00:00.000000Z"}`
	var out bytes.Buffer
	require.NoError(t, run(false, key, "", strings.NewReader(payload), &out))
	var signed map[string]string
	require.NoError(t, json.Unmarshal(out.Bytes(), &signed))
	assert.Equal(t, "deployment_owner", signed["basis"])

	raw, err := os.ReadFile(pub)
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	o := sdkauthz.OwnerConfirmation{Deployment: "dep-1", Target: "rec-1", CandidateDigest: "sha256:c", ExpiresAt: "2026-11-05T00:00:00.000000Z"}
	assert.True(t, o.Verify(k.(ed25519.PublicKey), signed["signature"]), "the member's check with the public key")
}
