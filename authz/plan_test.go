package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestItemState is security 08's item table: one run's result to the item's state.
func TestItemState(t *testing.T) {
	cases := []struct {
		res   changeResult
		state string
		wait  bool
	}{
		{changeResult{Outcome: "applied"}, itemApplied, false},
		{changeResult{Outcome: "scheduled", Record: "r"}, itemApplied, false},
		{changeResult{Outcome: "awaiting_confirmation", Record: "r", Reason: "CONFIRMATION_REQUIRED"}, itemNeedsReview, false},
		{changeResult{Outcome: "awaiting_confirmation", Reason: "CONFIRMATION_REQUIRED"}, itemNeedsReview, false},
		{changeResult{Outcome: "processing"}, itemPending, true},
		{changeResult{Outcome: "rejected", Retryable: true, Reason: "RECOVERY_IN_PROGRESS"}, itemPending, true},
		{changeResult{Outcome: "rejected", Reason: "CHANGE_REVISION_STALE"}, itemNeedsReview, false},
		{changeResult{Outcome: "rejected", Reason: "CONTAINMENT_NOT_PROVEN"}, itemRejected, false},
		{changeResult{Outcome: "rejected", Reason: "PERMISSION_DENIED"}, itemRejected, false},
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
