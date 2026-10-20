// Command seed gives infra/authz's seed data for people (be-assembly-standard's seed and test data conventions): the
// grants of the member's own operations. A management unit's admin (test.unit.admin.cn) reads and changes security
// records at the effect point, so it can grant within its unit; the units themselves, their scopes and the roles of
// business operations come from the seeds of the components that define those operations (the effect point accepts
// only defined resource types). Change keys are fixed, so a second run creates nothing.
//
//	SEED_IAM_URL (http://localhost:18200)    the identity member's development exchange
//	SEED_AUTHZ_URL (http://localhost:18223)  the effect point
//	SEED_ADMIN (test.alice)                  the authorization admin (the install claim)
//	SEED_PASSWORD                            the test accounts' password (infra/iam-casdoor's seed accounts)
//
// Run: go run ./cmd/seed (the identity and authorization members up).
package main

import (
	"fmt"
	"os"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/seed"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func check(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "seed infra/authz: %v\n", err)
		os.Exit(1)
	}
}

func main() {
	pw := os.Getenv("SEED_PASSWORD")
	if pw == "" {
		check(fmt.Errorf("SEED_PASSWORD is not set (the test accounts' password in Casdoor)"))
	}
	base, admin := env("SEED_AUTHZ_URL", "http://localhost:18223"), env("SEED_ADMIN", "test.alice")
	if !seed.Ready(base) { // probe before pouring
		check(fmt.Errorf("infra/authz at %s is not ready", base))
	}
	accounts, err := seed.Accounts(env("SEED_IAM_URL", "http://localhost:18200"), pw, admin, "test.unit.admin.cn")
	check(err)
	a, err := seed.NewAuthz(base, accounts[admin].Token, "infra/authz")
	check(err)
	segs := []sdkauthz.Segment{}
	for _, op := range []string{"infra.authz.security_record.read", "infra.authz.security_record.change"} {
		s := seed.Segment("infra.authz.security_record", op)
		s.ReadFields = []string{"id", "record_type", "state", "body"}
		segs = append(segs, s)
	}
	_, err = a.Grant("unit-admin", "", accounts["test.unit.admin.cn"].Principal, segs)
	check(err)
	// the unit's admin can use the effect point once the grant reaches the member's own view
	check(seed.NewClient(base, accounts["test.unit.admin.cn"].Token).WaitGranted("POST", "/api/authz/changes", 30*time.Second))
	fmt.Println("seed infra/authz: the unit admin test.unit.admin.cn reads and changes security records")
}
