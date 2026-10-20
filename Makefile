seed:  ## the seed data for people: grants of this member's own operations (SEED_PASSWORD; see cmd/seed)
	-$(MAKE) -C ../iam-casdoor seed   # the identity member's seed accounts first; skipped when Casdoor is not reachable
	go run ./cmd/seed
.PHONY: seed
