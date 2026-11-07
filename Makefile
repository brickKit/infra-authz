.PHONY: test test-integration lint seed

test:  ## unit tests: the decision table, the containment and intersection rules, the registry, submissions, the manifest, merge safety
	go vet ./... && go test ./...

test-integration:  ## L2 against PostgreSQL (AUTHZ_IT_PG_PASSWORD) and be-sdk-go's sectest deployment; see itest/AGENTS.md
	go test -count=1 -tags integration ./itest/

lint:
	brickkit lint

seed:  ## the seed data for people: grants of this member's own operations (SEED_PASSWORD; see cmd/seed)
	-$(MAKE) -C ../iam-casdoor seed   # the identity member's seed accounts first; skipped when Casdoor is not reachable
	go run ./cmd/seed
