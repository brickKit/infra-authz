package core

// The effect point's decision table (security 08, "生效点的结果"): every change that enters the effect point is
// described by the facts below, read inside its transaction, and the first matching row of the table decides it.
// decide does no reading itself, so each row is tested on its own.

// Kinds of change (security 08, "状态迁移"). Terminate is the tightening that ends a record not yet effective (an
// applicant's withdrawal, a confirmer's rejection, a cancellation).
const (
	Widen               = "widen"
	Tighten             = "tighten"
	Terminate           = "terminate"
	RestoreHold         = "restore_security_hold"
	RestoreUncomputable = "restore_uncomputable"
	Neutral             = "neutral"
)

// Triggers: a user's submission, the member's own job under a derived key (scheduled, confirmed, automatic
// restore), or the deployment owner's administrator recovery.
const (
	ByUser     = "user"
	ByJob      = "job"
	ByRecovery = "recovery"
)

// Proof is a three-valued fact; the zero value counts as unprovable, so a fact nobody set never lets a change pass.
type Proof int

const (
	Unprovable Proof = iota
	Proven
	Disproven
)

// Change key states (security 08, "变更键").
const (
	KeyFree      = ""
	KeyBoundSame = "same"  // bound, the same content
	KeyBoundElse = "other" // bound, other content
)

// Confirmations attached to a change.
const (
	confirmNone    = ""
	ConfirmValid   = "valid"
	ConfirmInvalid = "invalid" // expired, used, not for this content or version, or a confirmer not qualified now
)

// Facts are what the effect point knows of one change.
type Facts struct {
	Key     string
	Kind    string
	Trigger string
	// FromState: the record's current state is the event's start state; FromRevision: the request's (or the derived
	// key's) state revision is the record's current one. A new record has both.
	FromState, FromRevision bool
	// Recovery: the recovery credential checked from the call's channel, and the change among the recovery steps.
	RecoveryCredential, RecoveryStep bool
	// TerminatorEligible: the requester may end this record not yet effective (its applicant, an admin vetoing in a
	// cooling-off, or a confirmer qualified now who is not the applicant).
	TerminatorEligible bool
	// Rejection: the termination is a confirmer's rejection (row 9 holds it when the confirmer is not provable); a
	// manager's cancellation is checked like any tightening.
	Rejection bool
	// The requester: eligible now; quarantined; eligible by the last applied facts, and whether those need a second
	// person (security 03: the source's watermark older than T_tight, none, or the source stalled)
	Eligible    Proof
	Quarantined bool
	LastApplied bool
	BeyondTight bool
	// Basis is not decided on: a change applied on the last applied facts says so in its audit (security 03)
	Basis map[string]any
	// OwnerOnly is not decided on: a saved widening whose holding confirmations are the deployment owner's only (the
	// cooling-off, cooling.go)
	OwnerOnly bool
	// AffectsAdmins: the change affects an authorization admin holding's availability (or the index is incomplete).
	AffectsAdmins bool
	Confirmation  string
	// ConfirmersProvable: every attached confirmer's eligibility can be proven now (the exempt bases count as provable).
	ConfirmersProvable bool
	// RecoveryPending: the deployment awaits recovery or is in administrator recovery; ManagementWiden: the change widens
	// the management structure (units, holdings, system roles, account links).
	RecoveryPending, ManagementWiden bool
	MemberSwitch                     bool
	RevisionsChanged                 bool // a revision the record's validity depends on changed since the request
	Contained                        bool // containment proven (and a superseded record contained in the new one)
	OverBudget                       bool
	NeedsConfirmation                bool // a widening the profile wants confirmed
	TightenNeedsConfirmation         bool // the two-person rule, or a protected tightening
	RestoredEmpty                    bool // a restore whose effective segments are empty
	Disposition                      bool // a security disposition: never held back by the last admin
	AdminsAfter                      Proof
	Future                           bool // a widening effective in the future
	PartlyOutside                    bool // a restore partly outside its limits: effective and flagged for review
}

// Outcomes of the table.
const (
	outReturned          = "returned"           // the bound result again
	OutRejected          = "rejected"           // final
	OutRejectedRetryable = "rejected_retryable" // the key stays free
	OutVoid              = "void"               // a stale job: nothing changes
	OutApplied           = "applied"
	OutAppliedReview     = "applied_review"   // applied, flagged for review
	OutProcessing        = "processing"       // retried: by the caller, or the job waits
	OutAwaitingSaved     = "awaiting_saved"   // awaiting confirmation, the record saved
	OutAwaitingUnsaved   = "awaiting_unsaved" // awaiting confirmation, nothing saved
	OutKeptHeld          = "kept_held"
	OutScheduled         = "scheduled"
)

// Verdict is the table's answer: the row, its outcome and reason (security 09a).
type Verdict struct {
	Row     int
	Outcome string
	Reason  string
}

func in(v string, set ...string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

// Decide is the table, rows in order, the first that matches.
func Decide(f Facts) Verdict {
	tightens := in(f.Kind, Tighten, Terminate) // terminate is a tightening (security 08, "状态迁移")
	restores := in(f.Kind, RestoreHold, RestoreUncomputable)
	switch {
	case f.Key == KeyBoundSame:
		return Verdict{1, outReturned, ""}
	case f.Key == KeyBoundElse:
		return Verdict{2, OutRejected, "CHANGE_KEY_CONFLICT"}
	case f.Trigger == ByJob && (!f.FromState || !f.FromRevision):
		return Verdict{3, OutVoid, ""}
	case f.Trigger == ByUser && (!f.FromState || !f.FromRevision):
		return Verdict{4, OutRejected, "CHANGE_REVISION_STALE"}
	case f.Trigger == ByRecovery && f.RecoveryCredential && f.RecoveryStep && in(f.Kind, Tighten, Widen, RestoreHold):
		return Verdict{5, OutApplied, ""}
	case f.Trigger == ByRecovery:
		return Verdict{6, OutRejected, "PERMISSION_DENIED"}
	case f.Kind == Terminate && f.Trigger == ByUser && f.TerminatorEligible:
		return Verdict{7, OutApplied, ""}
	case f.Eligible == Disproven && (in(f.Kind, Widen, RestoreHold, Neutral) || tightens):
		return Verdict{8, OutRejected, "PERMISSION_DENIED"}
	case f.Eligible != Proven && (in(f.Kind, Widen, RestoreHold) || f.Kind == Terminate && f.Rejection):
		return Verdict{9, OutProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}
	case f.Eligible != Proven && tightens && f.Quarantined:
		return Verdict{10, OutRejectedRetryable, "AUTHORIZATION_UNPROVABLE"}
	case f.Eligible != Proven && tightens && !f.LastApplied:
		return Verdict{11, OutRejectedRetryable, "AUTHORIZATION_UNPROVABLE"}
	case f.Eligible != Proven && tightens && f.AffectsAdmins && f.Confirmation == confirmNone:
		return Verdict{12, OutProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}
	case f.RecoveryPending && f.ManagementWiden && (f.Kind == Widen || restores) && f.Trigger == ByUser:
		return Verdict{13, OutRejectedRetryable, "RECOVERY_IN_PROGRESS"}
	case f.RecoveryPending && f.ManagementWiden && (f.Kind == Widen || restores):
		return Verdict{14, OutProcessing, "RECOVERY_IN_PROGRESS"}
	case f.MemberSwitch && (f.Kind == Widen || restores) && f.Trigger == ByUser:
		return Verdict{15, OutRejectedRetryable, "MEMBER_SWITCH_IN_PROGRESS"}
	case f.MemberSwitch && (f.Kind == Widen || restores):
		return Verdict{16, OutProcessing, "MEMBER_SWITCH_IN_PROGRESS"}
	case f.RevisionsChanged:
		return Verdict{17, OutRejected, "CHANGE_REVISION_STALE"}
	case f.Kind == Widen && !f.Contained:
		return Verdict{18, OutRejected, "CONTAINMENT_NOT_PROVEN"}
	case f.Kind == Widen && f.OverBudget:
		return Verdict{19, OutRejected, "CONTAINMENT_NOT_PROVEN"}
	case f.Kind == Widen && f.NeedsConfirmation && f.Confirmation == confirmNone:
		return Verdict{20, OutAwaitingSaved, "CONFIRMATION_REQUIRED"}
	case in(f.Kind, Tighten, RestoreHold) && (f.TightenNeedsConfirmation || f.Eligible != Proven && f.BeyondTight) &&
		f.Confirmation == confirmNone:
		return Verdict{21, OutAwaitingUnsaved, "CONFIRMATION_REQUIRED"}
	case in(f.Kind, Widen, Tighten, RestoreHold) && f.Confirmation != confirmNone && !f.ConfirmersProvable:
		return Verdict{22, OutProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}
	case f.Kind == Widen && f.Confirmation == ConfirmInvalid:
		return Verdict{23, OutAwaitingSaved, "CONFIRMATION_REQUIRED"}
	case in(f.Kind, Tighten, RestoreHold) && f.Confirmation == ConfirmInvalid:
		return Verdict{24, OutAwaitingUnsaved, "CONFIRMATION_REQUIRED"}
	case restores && f.RestoredEmpty:
		return Verdict{25, OutKeptHeld, ""}
	case restores && f.OverBudget:
		return Verdict{26, OutKeptHeld, "CONTAINMENT_NOT_PROVEN"}
	case f.Kind == Tighten && f.AffectsAdmins && !f.Disposition && f.AdminsAfter == Disproven:
		return Verdict{27, OutRejected, "LAST_ADMIN_PROTECTED"}
	case f.Kind == Tighten && f.AffectsAdmins && !f.Disposition && f.AdminsAfter != Proven:
		return Verdict{28, OutProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}
	case f.Kind == Widen && f.Future:
		return Verdict{29, OutScheduled, ""}
	case restores && f.PartlyOutside:
		return Verdict{30, OutAppliedReview, ""}
	}
	return Verdict{30, OutApplied, ""}
}

// ReplayFacts sets aside the business preconditions of a replayed change.
func ReplayFacts(f Facts) Facts {
	f.Eligible, f.Quarantined, f.LastApplied, f.BeyondTight = Proven, false, false, false
	f.Contained, f.OverBudget, f.ConfirmersProvable = true, false, true
	f.NeedsConfirmation, f.TightenNeedsConfirmation = false, false
	f.RecoveryPending, f.MemberSwitch, f.RevisionsChanged, f.FromRevision = false, false, false, true
	f.AdminsAfter = Proven
	return f
}
