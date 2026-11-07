package plans

import (
	"testing"

	effectpoint "github.com/brickKit/infra-authz/v3/internal/effectpoint"

	"github.com/stretchr/testify/assert"
)

// TestItemState is security 08's item table: one run's result to the item's state.
func TestItemState(t *testing.T) {
	cases := []struct {
		res   effectpoint.ChangeResult
		state string
		wait  bool
	}{
		{effectpoint.ChangeResult{Outcome: "applied"}, ItemApplied, false},
		{effectpoint.ChangeResult{Outcome: "scheduled", Record: "r"}, ItemApplied, false},
		{effectpoint.ChangeResult{Outcome: "awaiting_confirmation", Record: "r", Reason: "CONFIRMATION_REQUIRED"}, ItemNeedsReview, false},
		{effectpoint.ChangeResult{Outcome: "awaiting_confirmation", Reason: "CONFIRMATION_REQUIRED"}, ItemNeedsReview, false},
		{effectpoint.ChangeResult{Outcome: "processing"}, ItemPending, true},
		{effectpoint.ChangeResult{Outcome: "rejected", Retryable: true, Reason: "RECOVERY_IN_PROGRESS"}, ItemPending, true},
		{effectpoint.ChangeResult{Outcome: "rejected", Reason: "CHANGE_REVISION_STALE"}, ItemNeedsReview, false},
		{effectpoint.ChangeResult{Outcome: "rejected", Reason: "CONTAINMENT_NOT_PROVEN"}, ItemRejected, false},
		{effectpoint.ChangeResult{Outcome: "rejected", Reason: "PERMISSION_DENIED"}, ItemRejected, false},
	}
	for _, c := range cases {
		state, wait := itemState(c.res)
		assert.Equal(t, c.state, state, "%+v", c.res)
		assert.Equal(t, c.wait, wait, "%+v", c.res)
	}
}

func TestItemKeyHasTheAttempt(t *testing.T) {
	assert.Equal(t, "plan:p1:a:2", itemKey("p1", "a", 2))
	assert.NotEqual(t, itemKey("p1", "a", 1), itemKey("p1", "a", 2), "a reviewed item runs under a new key")
}
