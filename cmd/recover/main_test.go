package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	adminrecovery "github.com/brickKit/infra-authz/v3/internal/adminrecovery"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTheRequestIsSignedAsTheMemberChecksIt: the printed request verifies with the public key against the digest
// the member computes.
func TestTheRequestIsSignedAsTheMemberChecksIt(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(sk)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "recovery.key.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	var out bytes.Buffer
	require.NoError(t, run(path, "dep-1", "replace", "", "", []string{"h1", "h2"}, &out))
	var got struct {
		Request   adminrecovery.RecoveryRequest `json:"request"`
		Signature string                        `json:"signature"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	assert.Equal(t, []string{"h1", "h2"}, got.Request.Holdings)
	assert.NotEmpty(t, got.Request.Nonce)
	d, err := got.Request.Digest()
	require.NoError(t, err)
	sig, err := base64.StdEncoding.DecodeString(got.Signature)
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(pk, []byte(d), sig))
	got.Request.Holdings = []string{"h1"}
	d2, _ := got.Request.Digest()
	assert.False(t, ed25519.Verify(pk, []byte(d2), sig), "the signature binds the holdings")
	assert.Error(t, run(path, "", "restore", "p", "", nil, &out))
}
