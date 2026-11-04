// Command owner-sign is the deployment owner's tool (security 08's owner confirmation, A124), meant for the machine
// that keeps the owner's private key offline:
//
//	owner-sign -keygen -key owner.key.pem -pub owner.pub.pem   generate the pair at installation; the public key goes
//	                                                           into the member's AUTHZ_OWNER_KEY
//	owner-sign -key owner.key.pem < payload.json               sign what the member answered on
//	                                                           GET /api/authz/confirmations/owner-payload?target=…
//
// The signature, with the payload's expires_at, is posted to POST /api/authz/confirmations with basis
// deployment_owner by whoever carries it: it binds that object only.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/seed"
)

func main() {
	keygen := flag.Bool("keygen", false, "generate the owner's key pair")
	key := flag.String("key", "", "the owner's private key (PEM, PKCS #8)")
	pub := flag.String("pub", "", "with -keygen: where the public key goes (PEM)")
	flag.Parse()
	if err := run(*keygen, *key, *pub, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "owner-sign:", err)
		os.Exit(1)
	}
}

func run(keygen bool, keyPath, pubPath string, in io.Reader, out io.Writer) error {
	if keyPath == "" {
		return fmt.Errorf("-key is required")
	}
	if keygen {
		if pubPath == "" {
			return fmt.Errorf("-keygen needs -pub")
		}
		pk, sk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		skDER, err := x509.MarshalPKCS8PrivateKey(sk)
		if err != nil {
			return err
		}
		pkDER, err := x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			return err
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: skDER}), 0o600); err != nil {
			return err
		}
		return os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkDER}), 0o644)
	}
	sk, err := seed.OwnerKey(keyPath)
	if err != nil {
		return err
	}
	var p struct {
		Deployment       string `json:"deployment"`
		Target           string `json:"target"`
		CandidateDigest  string `json:"candidate_digest"`
		ExpectedRevision string `json:"expected_revision"`
		ExpiresAt        string `json:"expires_at"`
	}
	if err := json.NewDecoder(in).Decode(&p); err != nil {
		return fmt.Errorf("the payload: %w", err)
	}
	sig, err := sdkauthz.OwnerConfirmation{Deployment: p.Deployment, Target: p.Target, CandidateDigest: p.CandidateDigest,
		ExpectedRevision: p.ExpectedRevision, ExpiresAt: p.ExpiresAt}.Sign(sk)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]string{"target": p.Target, "basis": "deployment_owner",
		"expires_at": p.ExpiresAt, "signature": sig})
}
