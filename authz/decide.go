package authz

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

// proof is a three-valued fact; the zero value counts as unprovable, so a fact nobody set never lets a change pass.
type proof int

const (
	unprovable proof = iota
	proven
	disproven
)

// Change key states (security 08, "变更键").
const (
	keyFree      = ""
	keyBoundSame = "same"  // bound, the same content
	keyBoundElse = "other" // bound, other content
)

// Confirmations attached to a change.
const (
	confirmNone    = ""
	confirmValid   = "valid"
	confirmInvalid = "invalid" // expired, used, not for this content or version, or a confirmer not qualified now
)

// facts are what the effect point knows of one change.
type facts struct {
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
	Eligible    proof
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
	AdminsAfter                      proof
	Future                           bool // a widening effective in the future
	PartlyOutside                    bool // a restore partly outside its limits: effective and flagged for review
}

// Outcomes of the table.
const (
	outReturned          = "returned"           // the bound result again
	outRejected          = "rejected"           // final
	outRejectedRetryable = "rejected_retryable" // the key stays free
	outVoid              = "void"               // a stale job: nothing changes
	outApplied           = "applied"
	outAppliedReview     = "applied_review"   // applied, flagged for review
	outProcessing        = "processing"       // retried: by the caller, or the job waits
	outAwaitingSaved     = "awaiting_saved"   // awaiting confirmation, the record saved
	outAwaitingUnsaved   = "awaiting_unsaved" // awaiting confirmation, nothing saved
	outKeptHeld          = "kept_held"
	outScheduled         = "scheduled"
)

// verdict is the table's answer: the row, its outcome and reason (security 09a).
type verdict struct {
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

// decide is the table, rows in order, the first that matches.
func decide(f facts) verdict {
	tightens := in(f.Kind, Tighten, Terminate) // terminate is a tightening (security 08, "状态迁移")
	restores := in(f.Kind, RestoreHold, RestoreUncomputable)
	switch {
	case f.Key == keyBoundSame:
		return verdict{1, outReturned, ""}
	case f.Key == keyBoundElse:
		return verdict{2, outRejected, "CHANGE_KEY_CONFLICT"}
	case f.Trigger == ByJob && (!f.FromState || !f.FromRevision):
		return verdict{3, outVoid, ""}
	case f.Trigger == ByUser && (!f.FromState || !f.FromRevision):
		return verdict{4, outRejected, "CHANGE_REVISION_STALE"}
	case f.Trigger == ByRecovery && f.RecoveryCredential && f.RecoveryStep && in(f.Kind, Tighten, Widen, RestoreHold):
		return verdict{5, outApplied, ""}
	case f.Trigger == ByRecovery:
		return verdict{6, outRejected, "PERMISSION_DENIED"}
	case f.Kind == Terminate && f.Trigger == ByUser && f.TerminatorEligible:
		return verdict{7, outApplied, ""}
	case f.Eligible == disproven && (in(f.Kind, Widen, RestoreHold, Neutral) || tightens):
		return verdict{8, outRejected, "PERMISSION_DENIED"}
	case f.Eligible != proven && (in(f.Kind, Widen, RestoreHold) || f.Kind == Terminate && f.Rejection):
		return verdict{9, outProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}
	case f.Eligible != proven && tightens && f.Quarantined:
		return verdict{10, outRejectedRetryable, "AUTHORIZATION_UNPROVABLE"}
	case f.Eligible != proven && tightens && !f.LastApplied:
		return verdict{11, outRejectedRetryable, "AUTHORIZATION_UNPROVABLE"}
	case f.Eligible != proven && tightens && f.AffectsAdmins && f.Confirmation == confirmNone:
		return verdict{12, outProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}
	case f.RecoveryPending && f.ManagementWiden && (f.Kind == Widen || restores) && f.Trigger == ByUser:
		return verdict{13, outRejectedRetryable, "RECOVERY_IN_PROGRESS"}
	case f.RecoveryPending && f.ManagementWiden && (f.Kind == Widen || restores):
		return verdict{14, outProcessing, "RECOVERY_IN_PROGRESS"}
	case f.MemberSwitch && (f.Kind == Widen || restores) && f.Trigger == ByUser:
		return verdict{15, outRejectedRetryable, "MEMBER_SWITCH_IN_PROGRESS"}
	case f.MemberSwitch && (f.Kind == Widen || restores):
		return verdict{16, outProcessing, "MEMBER_SWITCH_IN_PROGRESS"}
	case f.RevisionsChanged:
		return verdict{17, outRejected, "CHANGE_REVISION_STALE"}
	case f.Kind == Widen && !f.Contained:
		return verdict{18, outRejected, "CONTAINMENT_NOT_PROVEN"}
	case f.Kind == Widen && f.OverBudget:
		return verdict{19, outRejected, "CONTAINMENT_NOT_PROVEN"}
	case f.Kind == Widen && f.NeedsConfirmation && f.Confirmation == confirmNone:
		return verdict{20, outAwaitingSaved, "CONFIRMATION_REQUIRED"}
	case in(f.Kind, Tighten, RestoreHold) && (f.TightenNeedsConfirmation || f.Eligible != proven && f.BeyondTight) &&
		f.Confirmation == confirmNone:
		return verdict{21, outAwaitingUnsaved, "CONFIRMATION_REQUIRED"}
	case in(f.Kind, Widen, Tighten, RestoreHold) && f.Confirmation != confirmNone && !f.ConfirmersProvable:
		return verdict{22, outProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}
	case f.Kind == Widen && f.Confirmation == confirmInvalid:
		return verdict{23, outAwaitingSaved, "CONFIRMATION_REQUIRED"}
	case in(f.Kind, Tighten, RestoreHold) && f.Confirmation == confirmInvalid:
		return verdict{24, outAwaitingUnsaved, "CONFIRMATION_REQUIRED"}
	case restores && f.RestoredEmpty:
		return verdict{25, outKeptHeld, ""}
	case restores && f.OverBudget:
		return verdict{26, outKeptHeld, "CONTAINMENT_NOT_PROVEN"}
	case f.Kind == Tighten && f.AffectsAdmins && !f.Disposition && f.AdminsAfter == disproven:
		return verdict{27, outRejected, "LAST_ADMIN_PROTECTED"}
	case f.Kind == Tighten && f.AffectsAdmins && !f.Disposition && f.AdminsAfter != proven:
		return verdict{28, outProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}
	case f.Kind == Widen && f.Future:
		return verdict{29, outScheduled, ""}
	case restores && f.PartlyOutside:
		return verdict{30, outAppliedReview, ""}
	}
	return verdict{30, outApplied, ""}
}
