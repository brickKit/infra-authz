package effectpoint

import "fmt"

// The record's state transitions in one table (security 08, "状态迁移" and "结果对记录状态的作用"; docs/design.md,
// "记录的状态迁移"): from a stored state, with a held record's hold reason, to the states it may move to, with an
// ended record's end reason or a held record's hold reason. Transition refuses any other move: a decision that would
// write one is a defect, not a state. TestTheDesignDocumentHasTheMoves compares this table with the document.

// moves are the allowed transitions: the key is the state before ("" for a new record; held as held/<hold reason>),
// the values the states after (ended/<end reason>, held/<hold reason>).
var moves = map[string][]string{
	// a new record: saved for later, applied, or a final rejection of a new submission
	"": {"requested", "awaiting_confirmation", "scheduled", "active", "ended/rejected"},
	// not yet effective: through the effect point (saved again when its confirmations do not hold), or ended by a
	// termination or a final rejection of the job that brings it in
	"requested":             {"awaiting_confirmation", "scheduled", "active", "ended/rejected", "ended/withdrawn", "ended/cancelled"},
	"awaiting_confirmation": {"awaiting_confirmation", "scheduled", "active", "ended/rejected", "ended/withdrawn", "ended/cancelled"},
	"scheduled":             {"awaiting_confirmation", "active", "ended/rejected", "ended/withdrawn", "ended/cancelled"},
	// effective: a tightening, a disposition, the closure job's books, a renewal that contains it
	"active": {"held/security_hold", "held/uncomputable", "ended/revoked", "ended/relinquished", "ended/superseded",
		"ended/source_ended", "ended/source_narrowed", "ended/expired"},
	// held: restored, held by a disposition (another one, or an administrator recovery's), a release that leaves
	// nothing within its limits (restore_pending), or ended as an effective record is
	"held/security_hold": {"active", "held/security_hold", "held/restore_pending", "ended/revoked", "ended/relinquished",
		"ended/superseded", "ended/source_ended", "ended/source_narrowed", "ended/expired"},
	"held/uncomputable": {"active", "held/security_hold", "ended/revoked", "ended/relinquished", "ended/superseded",
		"ended/source_ended", "ended/source_narrowed", "ended/expired"},
	"held/restore_pending": {"active", "held/security_hold", "ended/revoked", "ended/relinquished", "ended/superseded",
		"ended/source_ended", "ended/source_narrowed", "ended/expired"},
	// ended: never revived; a new grant is a new record naming the old one as its predecessor
	"ended": {},
}

// stateOf is a state as the table names it: held and ended with their reason.
func stateOf(state, endReason, holdReason string) string {
	switch state {
	case "ended":
		return "ended/" + endReason
	case "held":
		return "held/" + holdReason
	}
	return state
}

// Allowed reports whether a record may move from (state, hold reason; "" for a new record) to (state, end reason,
// hold reason).
func Allowed(fromState, fromHold, state, endReason, holdReason string) bool {
	from := fromState
	if fromState == "held" {
		from = "held/" + fromHold
	}
	to := stateOf(state, endReason, holdReason)
	for _, m := range moves[from] {
		if m == to {
			return true
		}
	}
	return false
}

// refused is the error of a move the table does not allow.
func refused(id, fromState, fromHold, state, endReason, holdReason string) error {
	from := fromState
	if fromState == "held" {
		from += "/" + fromHold
	}
	if from == "" {
		from = "(new)"
	}
	return fmt.Errorf("effectpoint: record %s cannot move from %s to %s (security 08's transitions)", id, from,
		stateOf(state, endReason, holdReason))
}
