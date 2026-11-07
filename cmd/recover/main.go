// Command recover is the deployment owner's administrator recovery (security 08, A129), run on the deployment machine
// with the offline recovery key (generate the pair with owner-sign -keygen; its public key goes into the member's
// AUTHZ_RECOVERY_KEY, never the same pair as AUTHZ_OWNER_KEY):
//
//	recover -key recovery.key.pem -deployment D -action replace -holding H1 -holding H2   hold compromised admins
//	recover -key recovery.key.pem -deployment D -action restore -identity P              restore P as an admin
//	recover -key recovery.key.pem -deployment D -action abort                            back to before the recovery
//
// It prints the signed request (a nonce used once, valid for ten minutes); with -url it posts it to the member's
// POST /api/authz/recovery and prints the answer.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	adminrecovery "github.com/brickKit/infra-authz/v3/internal/adminrecovery"

	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/seed"
)

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	var holdings list
	key := flag.String("key", "", "the recovery private key (PEM, PKCS #8)")
	deployment := flag.String("deployment", "", "the deployment's identity (DEPLOYMENT_ID)")
	action := flag.String("action", "", "replace, restore or abort")
	identity := flag.String("identity", "", "restore: the platform principal to restore as an authorization admin")
	url := flag.String("url", "", "the member's user surface; empty: print the request only")
	flag.Var(&holdings, "holding", "replace: an authorization admin holding to hold (repeatable)")
	flag.Parse()
	if err := run(*key, *deployment, *action, *identity, *url, holdings, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "recover:", err)
		os.Exit(1)
	}
}

func run(keyPath, deployment, action, identity, url string, holdings []string, out io.Writer) error {
	if keyPath == "" || deployment == "" || action == "" {
		return fmt.Errorf("-key, -deployment and -action are required")
	}
	sk, err := seed.OwnerKey(keyPath)
	if err != nil {
		return err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	r := adminrecovery.RecoveryRequest{Deployment: deployment, Action: action, Holdings: holdings, Identity: identity,
		Nonce: hex.EncodeToString(nonce), ExpiresAt: canon.Time(time.Now().Add(10 * time.Minute))}
	sig, err := r.Sign(sk)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"request": r, "signature": sig})
	if err != nil {
		return err
	}
	if url == "" {
		_, err = fmt.Fprintln(out, string(body))
		return err
	}
	resp, err := http.Post(strings.TrimRight(url, "/")+"/api/authz/recovery", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("%d %s", resp.StatusCode, answer)
	}
	_, err = fmt.Fprintln(out, string(answer))
	return err
}
