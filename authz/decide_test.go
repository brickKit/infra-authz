package authz

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// passing is a change of the kind that every row lets through: the cases below each break one fact.
func passing(kind, trigger string) facts {
	return facts{Kind: kind, Trigger: trigger, FromState: true, FromRevision: true, Eligible: proven, LastApplied: true,
		Contained: true, ConfirmersProvable: true, AdminsAfter: proven}
}

func with(f facts, change func(*facts)) facts {
	change(&f)
	return f
}

// TestTheDecisionTable: security 08's "生效点的结果", row by row, written from the table.
func TestTheDecisionTable(t *testing.T) {
	cases := []struct {
		name string
		in   facts
		want verdict
	}{
		{"bound key, same content", with(passing(Widen, ByUser), func(f *facts) { f.Key = keyBoundSame }),
			verdict{1, outReturned, ""}},
		{"bound key, other content", with(passing(Tighten, ByUser), func(f *facts) { f.Key = keyBoundElse }),
			verdict{2, outRejected, "CHANGE_KEY_CONFLICT"}},
		{"bound key beats a stale revision", with(passing(Tighten, ByUser), func(f *facts) { f.Key = keyBoundElse; f.FromRevision = false }),
			verdict{2, outRejected, "CHANGE_KEY_CONFLICT"}},
		{"a job whose derived key's revision is stale", with(passing(Widen, ByJob), func(f *facts) { f.FromRevision = false }),
			verdict{3, outVoid, ""}},
		{"a job whose record left its start state", with(passing(RestoreUncomputable, ByJob), func(f *facts) { f.FromState = false }),
			verdict{3, outVoid, ""}},
		{"a user's change on a record in another state", with(passing(Terminate, ByUser), func(f *facts) { f.FromState = false }),
			verdict{4, outRejected, "CHANGE_REVISION_STALE"}},
		{"a user's change at a stale revision", with(passing(Tighten, ByUser), func(f *facts) { f.FromRevision = false }),
			verdict{4, outRejected, "CHANGE_REVISION_STALE"}},
		{"administrator recovery, a listed step", with(passing(Widen, ByRecovery), func(f *facts) {
			f.RecoveryCredential, f.RecoveryStep, f.Eligible, f.Contained, f.NeedsConfirmation = true, true, disproven, false, true
		}), verdict{5, outApplied, ""}},
		{"administrator recovery's tightening", with(passing(Tighten, ByRecovery), func(f *facts) {
			f.RecoveryCredential, f.RecoveryStep, f.AffectsAdmins, f.AdminsAfter = true, true, true, disproven
		}), verdict{5, outApplied, ""}},
		{"recovery without the credential", with(passing(RestoreHold, ByRecovery), func(f *facts) { f.RecoveryStep = true }),
			verdict{6, outRejected, "PERMISSION_DENIED"}},
		{"recovery, a change not among the steps", with(passing(Widen, ByRecovery), func(f *facts) { f.RecoveryCredential = true }),
			verdict{6, outRejected, "PERMISSION_DENIED"}},
		{"the applicant withdraws, whatever the admins", with(passing(Terminate, ByUser), func(f *facts) {
			f.TerminatorEligible, f.Eligible, f.AffectsAdmins, f.AdminsAfter = true, disproven, true, disproven
		}), verdict{7, outApplied, ""}},
		{"a widening by someone not eligible", with(passing(Widen, ByUser), func(f *facts) { f.Eligible = disproven }),
			verdict{8, outRejected, "PERMISSION_DENIED"}},
		{"a scheduled widening whose requester lost eligibility", with(passing(Widen, ByJob), func(f *facts) { f.Eligible = disproven }),
			verdict{8, outRejected, "PERMISSION_DENIED"}},
		{"a neutral change by someone not eligible", with(passing(Neutral, ByUser), func(f *facts) { f.Eligible = disproven }),
			verdict{8, outRejected, "PERMISSION_DENIED"}},
		{"a cancellation by someone not eligible", with(passing(Terminate, ByUser), func(f *facts) { f.Eligible = disproven }),
			verdict{8, outRejected, "PERMISSION_DENIED"}},
		{"not eligible beats a changed revision", with(passing(Tighten, ByUser), func(f *facts) { f.Eligible = disproven; f.RevisionsChanged = true }),
			verdict{8, outRejected, "PERMISSION_DENIED"}},
		{"an automatic restore re-checks nobody (D36)", with(passing(RestoreUncomputable, ByJob), func(f *facts) { f.Eligible = disproven }),
			verdict{30, outApplied, ""}},
		{"a widening whose requester cannot be proven", with(passing(Widen, ByUser), func(f *facts) { f.Eligible = unprovable }),
			verdict{9, outProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}},
		{"releasing a hold, the releaser not provable", with(passing(RestoreHold, ByUser), func(f *facts) { f.Eligible = unprovable }),
			verdict{9, outProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}},
		{"a confirmer's rejection, the confirmer not provable", with(passing(Terminate, ByUser), func(f *facts) { f.Eligible = unprovable; f.Rejection = true }),
			verdict{9, outProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}},
		{"a manager's cancellation, not provable, not eligible by the last applied facts", with(passing(Terminate, ByUser), func(f *facts) {
			f.Eligible, f.LastApplied = unprovable, false
		}), verdict{11, outRejectedRetryable, "AUTHORIZATION_UNPROVABLE"}},
		{"a manager's cancellation by the last applied facts", with(passing(Terminate, ByUser), func(f *facts) { f.Eligible = unprovable }),
			verdict{30, outApplied, ""}},
		{"an unset eligibility is unprovable", with(passing(Widen, ByUser), func(f *facts) { f.Eligible = 0 }),
			verdict{9, outProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}},
		{"a tightening, the requester quarantined", with(passing(Tighten, ByUser), func(f *facts) { f.Eligible = unprovable; f.Quarantined = true }),
			verdict{10, outRejectedRetryable, "AUTHORIZATION_UNPROVABLE"}},
		{"a tightening, not eligible by the last applied facts", with(passing(Tighten, ByJob), func(f *facts) { f.Eligible = unprovable; f.LastApplied = false }),
			verdict{11, outRejectedRetryable, "AUTHORIZATION_UNPROVABLE"}},
		{"a tightening of an admin, unprovable, no confirmation", with(passing(Tighten, ByUser), func(f *facts) { f.Eligible = unprovable; f.AffectsAdmins = true }),
			verdict{12, outProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}},
		{"a tightening by the last applied facts, not of an admin", with(passing(Tighten, ByUser), func(f *facts) { f.Eligible = unprovable }),
			verdict{30, outApplied, ""}},
		{"a management widening while recovering", with(passing(Widen, ByUser), func(f *facts) { f.RecoveryPending, f.ManagementWiden = true, true }),
			verdict{13, outRejectedRetryable, "RECOVERY_IN_PROGRESS"}},
		{"releasing a hold on a holding while recovering", with(passing(RestoreHold, ByUser), func(f *facts) { f.RecoveryPending, f.ManagementWiden = true, true }),
			verdict{13, outRejectedRetryable, "RECOVERY_IN_PROGRESS"}},
		{"a scheduled management widening while recovering", with(passing(Widen, ByJob), func(f *facts) { f.RecoveryPending, f.ManagementWiden = true, true }),
			verdict{14, outProcessing, "RECOVERY_IN_PROGRESS"}},
		{"an ordinary widening while recovering", with(passing(Widen, ByUser), func(f *facts) { f.RecoveryPending = true }),
			verdict{30, outApplied, ""}},
		{"a widening while the member switches", with(passing(Widen, ByUser), func(f *facts) { f.MemberSwitch = true }),
			verdict{15, outRejectedRetryable, "MEMBER_SWITCH_IN_PROGRESS"}},
		{"an automatic restore while the member switches", with(passing(RestoreUncomputable, ByJob), func(f *facts) { f.MemberSwitch = true }),
			verdict{16, outProcessing, "MEMBER_SWITCH_IN_PROGRESS"}},
		{"a tightening while the member switches", with(passing(Tighten, ByUser), func(f *facts) { f.MemberSwitch = true }),
			verdict{30, outApplied, ""}},
		{"a revision the record depends on changed", with(passing(Tighten, ByUser), func(f *facts) { f.RevisionsChanged = true }),
			verdict{17, outRejected, "CHANGE_REVISION_STALE"}},
		{"a changed revision beats containment", with(passing(Widen, ByJob), func(f *facts) { f.RevisionsChanged = true; f.Contained = false }),
			verdict{17, outRejected, "CHANGE_REVISION_STALE"}},
		{"containment not proven", with(passing(Widen, ByUser), func(f *facts) { f.Contained = false }),
			verdict{18, outRejected, "CONTAINMENT_NOT_PROVEN"}},
		{"a tightening needs no containment", with(passing(Tighten, ByUser), func(f *facts) { f.Contained = false }),
			verdict{30, outApplied, ""}},
		{"over budget", with(passing(Widen, ByUser), func(f *facts) { f.OverBudget = true }),
			verdict{19, outRejected, "CONTAINMENT_NOT_PROVEN"}},
		{"containment beats confirmation", with(passing(Widen, ByUser), func(f *facts) { f.Contained = false; f.NeedsConfirmation = true }),
			verdict{18, outRejected, "CONTAINMENT_NOT_PROVEN"}},
		{"a widening the profile wants confirmed", with(passing(Widen, ByUser), func(f *facts) { f.NeedsConfirmation = true }),
			verdict{20, outAwaitingSaved, "CONFIRMATION_REQUIRED"}},
		{"a tightening under the two-person rule", with(passing(Tighten, ByUser), func(f *facts) { f.TightenNeedsConfirmation = true }),
			verdict{21, outAwaitingUnsaved, "CONFIRMATION_REQUIRED"}},
		{"releasing a hold of another admin", with(passing(RestoreHold, ByUser), func(f *facts) { f.TightenNeedsConfirmation = true }),
			verdict{21, outAwaitingUnsaved, "CONFIRMATION_REQUIRED"}},
		{"a cancellation never waits for a confirmation", with(passing(Terminate, ByUser), func(f *facts) { f.TightenNeedsConfirmation = true }),
			verdict{30, outApplied, ""}},
		{"a confirmer not provable", with(passing(Widen, ByUser), func(f *facts) {
			f.NeedsConfirmation, f.Confirmation, f.ConfirmersProvable = true, confirmValid, false
		}), verdict{22, outProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}},
		{"an invalid confirmation of a widening", with(passing(Widen, ByJob), func(f *facts) { f.NeedsConfirmation, f.Confirmation = true, confirmInvalid }),
			verdict{23, outAwaitingSaved, "CONFIRMATION_REQUIRED"}},
		{"an invalid confirmation of a tightening", with(passing(Tighten, ByUser), func(f *facts) {
			f.TightenNeedsConfirmation, f.Confirmation = true, confirmInvalid
		}), verdict{24, outAwaitingUnsaved, "CONFIRMATION_REQUIRED"}},
		{"a confirmed widening", with(passing(Widen, ByUser), func(f *facts) { f.NeedsConfirmation, f.Confirmation = true, confirmValid }),
			verdict{30, outApplied, ""}},
		{"a restore with nothing left", with(passing(RestoreUncomputable, ByJob), func(f *facts) { f.RestoredEmpty = true }),
			verdict{25, outKeptHeld, ""}},
		{"a restore over budget", with(passing(RestoreHold, ByUser), func(f *facts) { f.OverBudget = true }),
			verdict{26, outKeptHeld, "CONTAINMENT_NOT_PROVEN"}},
		{"the last admin", with(passing(Tighten, ByUser), func(f *facts) { f.AffectsAdmins, f.AdminsAfter = true, disproven }),
			verdict{27, outRejected, "LAST_ADMIN_PROTECTED"}},
		{"the last admin, by a job", with(passing(Tighten, ByJob), func(f *facts) { f.AffectsAdmins, f.AdminsAfter = true, disproven }),
			verdict{27, outRejected, "LAST_ADMIN_PROTECTED"}},
		{"a disposition may leave no admin", with(passing(Tighten, ByUser), func(f *facts) {
			f.AffectsAdmins, f.AdminsAfter, f.Disposition = true, disproven, true
		}), verdict{30, outApplied, ""}},
		{"admins after the change not provable", with(passing(Tighten, ByUser), func(f *facts) { f.AffectsAdmins, f.AdminsAfter = true, unprovable }),
			verdict{28, outProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}},
		{"a change that does not affect admins is not counted", with(passing(Tighten, ByUser), func(f *facts) { f.AdminsAfter = disproven }),
			verdict{30, outApplied, ""}},
		{"a widening effective in the future", with(passing(Widen, ByUser), func(f *facts) { f.Future = true }),
			verdict{29, outScheduled, ""}},
		{"a widening", passing(Widen, ByUser), verdict{30, outApplied, ""}},
		{"a tightening", passing(Tighten, ByJob), verdict{30, outApplied, ""}},
		{"a restore partly outside its limits", with(passing(RestoreHold, ByUser), func(f *facts) { f.PartlyOutside = true }),
			verdict{30, outAppliedReview, ""}},
	}
	rows := map[int]bool{}
	for _, c := range cases {
		assert.Equal(t, c.want, decide(c.in), c.name)
		rows[c.want.Row] = true
	}
	for r := 1; r <= 30; r++ {
		assert.True(t, rows[r], fmt.Sprintf("row %d has a case", r))
	}
}
