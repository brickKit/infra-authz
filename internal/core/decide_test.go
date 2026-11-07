package core

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// passing is a change of the kind that every row lets through: the cases below each break one fact.
func passing(kind, trigger string) Facts {
	return Facts{Kind: kind, Trigger: trigger, FromState: true, FromRevision: true, Eligible: Proven, LastApplied: true,
		Contained: true, ConfirmersProvable: true, AdminsAfter: Proven}
}

func with(f Facts, change func(*Facts)) Facts {
	change(&f)
	return f
}

// TestTheDecisionTable: security 08's "生效点的结果", row by row, written from the table.
func TestTheDecisionTable(t *testing.T) {
	cases := []struct {
		name string
		in   Facts
		want Verdict
	}{
		{"bound key, same content", with(passing(Widen, ByUser), func(f *Facts) { f.Key = KeyBoundSame }),
			Verdict{1, outReturned, ""}},
		{"bound key, other content", with(passing(Tighten, ByUser), func(f *Facts) { f.Key = KeyBoundElse }),
			Verdict{2, OutRejected, "CHANGE_KEY_CONFLICT"}},
		{"bound key beats a stale revision", with(passing(Tighten, ByUser), func(f *Facts) { f.Key = KeyBoundElse; f.FromRevision = false }),
			Verdict{2, OutRejected, "CHANGE_KEY_CONFLICT"}},
		{"a job whose derived key's revision is stale", with(passing(Widen, ByJob), func(f *Facts) { f.FromRevision = false }),
			Verdict{3, OutVoid, ""}},
		{"a job whose record left its start state", with(passing(RestoreUncomputable, ByJob), func(f *Facts) { f.FromState = false }),
			Verdict{3, OutVoid, ""}},
		{"a user's change on a record in another state", with(passing(Terminate, ByUser), func(f *Facts) { f.FromState = false }),
			Verdict{4, OutRejected, "CHANGE_REVISION_STALE"}},
		{"a user's change at a stale revision", with(passing(Tighten, ByUser), func(f *Facts) { f.FromRevision = false }),
			Verdict{4, OutRejected, "CHANGE_REVISION_STALE"}},
		{"administrator recovery, a listed step", with(passing(Widen, ByRecovery), func(f *Facts) {
			f.RecoveryCredential, f.RecoveryStep, f.Eligible, f.Contained, f.NeedsConfirmation = true, true, Disproven, false, true
		}), Verdict{5, OutApplied, ""}},
		{"administrator recovery's tightening", with(passing(Tighten, ByRecovery), func(f *Facts) {
			f.RecoveryCredential, f.RecoveryStep, f.AffectsAdmins, f.AdminsAfter = true, true, true, Disproven
		}), Verdict{5, OutApplied, ""}},
		{"recovery without the credential", with(passing(RestoreHold, ByRecovery), func(f *Facts) { f.RecoveryStep = true }),
			Verdict{6, OutRejected, "PERMISSION_DENIED"}},
		{"recovery, a change not among the steps", with(passing(Widen, ByRecovery), func(f *Facts) { f.RecoveryCredential = true }),
			Verdict{6, OutRejected, "PERMISSION_DENIED"}},
		{"the applicant withdraws, whatever the admins", with(passing(Terminate, ByUser), func(f *Facts) {
			f.TerminatorEligible, f.Eligible, f.AffectsAdmins, f.AdminsAfter = true, Disproven, true, Disproven
		}), Verdict{7, OutApplied, ""}},
		{"a widening by someone not eligible", with(passing(Widen, ByUser), func(f *Facts) { f.Eligible = Disproven }),
			Verdict{8, OutRejected, "PERMISSION_DENIED"}},
		{"a scheduled widening whose requester lost eligibility", with(passing(Widen, ByJob), func(f *Facts) { f.Eligible = Disproven }),
			Verdict{8, OutRejected, "PERMISSION_DENIED"}},
		{"a neutral change by someone not eligible", with(passing(Neutral, ByUser), func(f *Facts) { f.Eligible = Disproven }),
			Verdict{8, OutRejected, "PERMISSION_DENIED"}},
		{"a cancellation by someone not eligible", with(passing(Terminate, ByUser), func(f *Facts) { f.Eligible = Disproven }),
			Verdict{8, OutRejected, "PERMISSION_DENIED"}},
		{"not eligible beats a changed revision", with(passing(Tighten, ByUser), func(f *Facts) { f.Eligible = Disproven; f.RevisionsChanged = true }),
			Verdict{8, OutRejected, "PERMISSION_DENIED"}},
		{"an automatic restore re-checks nobody (D36)", with(passing(RestoreUncomputable, ByJob), func(f *Facts) { f.Eligible = Disproven }),
			Verdict{30, OutApplied, ""}},
		{"a widening whose requester cannot be proven", with(passing(Widen, ByUser), func(f *Facts) { f.Eligible = Unprovable }),
			Verdict{9, OutProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}},
		{"releasing a hold, the releaser not provable", with(passing(RestoreHold, ByUser), func(f *Facts) { f.Eligible = Unprovable }),
			Verdict{9, OutProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}},
		{"a confirmer's rejection, the confirmer not provable", with(passing(Terminate, ByUser), func(f *Facts) { f.Eligible = Unprovable; f.Rejection = true }),
			Verdict{9, OutProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}},
		{"a manager's cancellation, not provable, not eligible by the last applied facts", with(passing(Terminate, ByUser), func(f *Facts) {
			f.Eligible, f.LastApplied = Unprovable, false
		}), Verdict{11, OutRejectedRetryable, "AUTHORIZATION_UNPROVABLE"}},
		{"a manager's cancellation by the last applied facts", with(passing(Terminate, ByUser), func(f *Facts) { f.Eligible = Unprovable }),
			Verdict{30, OutApplied, ""}},
		{"an unset eligibility is unprovable", with(passing(Widen, ByUser), func(f *Facts) { f.Eligible = 0 }),
			Verdict{9, OutProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}},
		{"a tightening, the requester quarantined", with(passing(Tighten, ByUser), func(f *Facts) { f.Eligible = Unprovable; f.Quarantined = true }),
			Verdict{10, OutRejectedRetryable, "AUTHORIZATION_UNPROVABLE"}},
		{"a tightening, not eligible by the last applied facts", with(passing(Tighten, ByJob), func(f *Facts) { f.Eligible = Unprovable; f.LastApplied = false }),
			Verdict{11, OutRejectedRetryable, "AUTHORIZATION_UNPROVABLE"}},
		{"a tightening of an admin, unprovable, no confirmation", with(passing(Tighten, ByUser), func(f *Facts) { f.Eligible = Unprovable; f.AffectsAdmins = true }),
			Verdict{12, OutProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}},
		{"a tightening by the last applied facts, not of an admin", with(passing(Tighten, ByUser), func(f *Facts) { f.Eligible = Unprovable }),
			Verdict{30, OutApplied, ""}},
		{"a management widening while recovering", with(passing(Widen, ByUser), func(f *Facts) { f.RecoveryPending, f.ManagementWiden = true, true }),
			Verdict{13, OutRejectedRetryable, "RECOVERY_IN_PROGRESS"}},
		{"releasing a hold on a holding while recovering", with(passing(RestoreHold, ByUser), func(f *Facts) { f.RecoveryPending, f.ManagementWiden = true, true }),
			Verdict{13, OutRejectedRetryable, "RECOVERY_IN_PROGRESS"}},
		{"a scheduled management widening while recovering", with(passing(Widen, ByJob), func(f *Facts) { f.RecoveryPending, f.ManagementWiden = true, true }),
			Verdict{14, OutProcessing, "RECOVERY_IN_PROGRESS"}},
		{"an ordinary widening while recovering", with(passing(Widen, ByUser), func(f *Facts) { f.RecoveryPending = true }),
			Verdict{30, OutApplied, ""}},
		{"a widening while the member switches", with(passing(Widen, ByUser), func(f *Facts) { f.MemberSwitch = true }),
			Verdict{15, OutRejectedRetryable, "MEMBER_SWITCH_IN_PROGRESS"}},
		{"an automatic restore while the member switches", with(passing(RestoreUncomputable, ByJob), func(f *Facts) { f.MemberSwitch = true }),
			Verdict{16, OutProcessing, "MEMBER_SWITCH_IN_PROGRESS"}},
		{"a tightening while the member switches", with(passing(Tighten, ByUser), func(f *Facts) { f.MemberSwitch = true }),
			Verdict{30, OutApplied, ""}},
		{"a revision the record depends on changed", with(passing(Tighten, ByUser), func(f *Facts) { f.RevisionsChanged = true }),
			Verdict{17, OutRejected, "CHANGE_REVISION_STALE"}},
		{"a changed revision beats containment", with(passing(Widen, ByJob), func(f *Facts) { f.RevisionsChanged = true; f.Contained = false }),
			Verdict{17, OutRejected, "CHANGE_REVISION_STALE"}},
		{"containment not proven", with(passing(Widen, ByUser), func(f *Facts) { f.Contained = false }),
			Verdict{18, OutRejected, "CONTAINMENT_NOT_PROVEN"}},
		{"a tightening needs no containment", with(passing(Tighten, ByUser), func(f *Facts) { f.Contained = false }),
			Verdict{30, OutApplied, ""}},
		{"over budget", with(passing(Widen, ByUser), func(f *Facts) { f.OverBudget = true }),
			Verdict{19, OutRejected, "CONTAINMENT_NOT_PROVEN"}},
		{"containment beats confirmation", with(passing(Widen, ByUser), func(f *Facts) { f.Contained = false; f.NeedsConfirmation = true }),
			Verdict{18, OutRejected, "CONTAINMENT_NOT_PROVEN"}},
		{"a widening the profile wants confirmed", with(passing(Widen, ByUser), func(f *Facts) { f.NeedsConfirmation = true }),
			Verdict{20, OutAwaitingSaved, "CONFIRMATION_REQUIRED"}},
		{"a protected tightening", with(passing(Tighten, ByUser), func(f *Facts) { f.TightenNeedsConfirmation = true }),
			Verdict{21, OutAwaitingUnsaved, "CONFIRMATION_REQUIRED"}},
		{"a tightening by the last applied facts beyond T_tight (security 03's two-person rule)", with(passing(Tighten, ByUser),
			func(f *Facts) { f.Eligible, f.BeyondTight = Unprovable, true }), Verdict{21, OutAwaitingUnsaved, "CONFIRMATION_REQUIRED"}},
		{"beyond T_tight, the second person confirmed", with(passing(Tighten, ByUser), func(f *Facts) {
			f.Eligible, f.BeyondTight, f.Confirmation = Unprovable, true, ConfirmValid
		}), Verdict{30, OutApplied, ""}},
		{"beyond T_tight does not count for a requester proven now", with(passing(Tighten, ByUser), func(f *Facts) { f.BeyondTight = true }),
			Verdict{30, OutApplied, ""}},
		{"a cancellation beyond T_tight is not held for a second person", with(passing(Terminate, ByUser), func(f *Facts) {
			f.Eligible, f.BeyondTight = Unprovable, true
		}), Verdict{30, OutApplied, ""}},
		{"releasing a hold of another admin", with(passing(RestoreHold, ByUser), func(f *Facts) { f.TightenNeedsConfirmation = true }),
			Verdict{21, OutAwaitingUnsaved, "CONFIRMATION_REQUIRED"}},
		{"a cancellation never waits for a confirmation", with(passing(Terminate, ByUser), func(f *Facts) { f.TightenNeedsConfirmation = true }),
			Verdict{30, OutApplied, ""}},
		{"a confirmer not provable", with(passing(Widen, ByUser), func(f *Facts) {
			f.NeedsConfirmation, f.Confirmation, f.ConfirmersProvable = true, ConfirmValid, false
		}), Verdict{22, OutProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}},
		{"an invalid confirmation of a widening", with(passing(Widen, ByJob), func(f *Facts) { f.NeedsConfirmation, f.Confirmation = true, ConfirmInvalid }),
			Verdict{23, OutAwaitingSaved, "CONFIRMATION_REQUIRED"}},
		{"an invalid confirmation of a tightening", with(passing(Tighten, ByUser), func(f *Facts) {
			f.TightenNeedsConfirmation, f.Confirmation = true, ConfirmInvalid
		}), Verdict{24, OutAwaitingUnsaved, "CONFIRMATION_REQUIRED"}},
		{"a confirmed widening", with(passing(Widen, ByUser), func(f *Facts) { f.NeedsConfirmation, f.Confirmation = true, ConfirmValid }),
			Verdict{30, OutApplied, ""}},
		{"a restore with nothing left", with(passing(RestoreUncomputable, ByJob), func(f *Facts) { f.RestoredEmpty = true }),
			Verdict{25, OutKeptHeld, ""}},
		{"a restore over budget", with(passing(RestoreHold, ByUser), func(f *Facts) { f.OverBudget = true }),
			Verdict{26, OutKeptHeld, "CONTAINMENT_NOT_PROVEN"}},
		{"the last admin", with(passing(Tighten, ByUser), func(f *Facts) { f.AffectsAdmins, f.AdminsAfter = true, Disproven }),
			Verdict{27, OutRejected, "LAST_ADMIN_PROTECTED"}},
		{"the last admin, by a job", with(passing(Tighten, ByJob), func(f *Facts) { f.AffectsAdmins, f.AdminsAfter = true, Disproven }),
			Verdict{27, OutRejected, "LAST_ADMIN_PROTECTED"}},
		{"a disposition may leave no admin", with(passing(Tighten, ByUser), func(f *Facts) {
			f.AffectsAdmins, f.AdminsAfter, f.Disposition = true, Disproven, true
		}), Verdict{30, OutApplied, ""}},
		{"admins after the change not provable", with(passing(Tighten, ByUser), func(f *Facts) { f.AffectsAdmins, f.AdminsAfter = true, Unprovable }),
			Verdict{28, OutProcessing, "ADMIN_AVAILABILITY_UNPROVABLE"}},
		{"a change that does not affect admins is not counted", with(passing(Tighten, ByUser), func(f *Facts) { f.AdminsAfter = Disproven }),
			Verdict{30, OutApplied, ""}},
		{"a widening effective in the future", with(passing(Widen, ByUser), func(f *Facts) { f.Future = true }),
			Verdict{29, OutScheduled, ""}},
		{"a widening", passing(Widen, ByUser), Verdict{30, OutApplied, ""}},
		{"a tightening", passing(Tighten, ByJob), Verdict{30, OutApplied, ""}},
		{"a restore partly outside its limits", with(passing(RestoreHold, ByUser), func(f *Facts) { f.PartlyOutside = true }),
			Verdict{30, OutAppliedReview, ""}},
	}
	rows := map[int]bool{}
	for _, c := range cases {
		assert.Equal(t, c.want, Decide(c.in), c.name)
		rows[c.want.Row] = true
	}
	for r := 1; r <= 30; r++ {
		assert.True(t, rows[r], fmt.Sprintf("row %d has a case", r))
	}
}
