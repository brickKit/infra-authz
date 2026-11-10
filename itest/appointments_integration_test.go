//go:build integration

package itest

import (
	"slices"
	"testing"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAppointmentBindings is C1's E4e (security 04 "任职事实与授予生命周期", D30; security 08's closure), on a
// deployment with the stand-in employee member: a grant or a management holding may bind an appointment of the
// grantee's employee, planned or active when it is made; it gives access only while the appointment is active and
// the account linked to the employee; when the appointment ends (a transfer makes a new one) or the link ends, the view
// leaves it out at once and the closure books it ended (source_ended). A new appointment gets nothing by itself.
func TestAppointmentBindings(t *testing.T) {
	e := startE2E(t, withEmployee)
	e.definitionsAndViews()
	w, ctx, admin, emp := e.w, e.ctx, e.admin, e.emp
	units := listRecords(t, w, sectest.Alice, "management_unit")
	require.Len(t, units, 1)
	root := units[0]["id"].(string)
	regions := func(p string) []string {
		var out []string
		for _, s := range e.segmentsOf(p) {
			if s.ResourceType == "demo.order" {
				out = append(out, s.Atoms["region"].Values...)
			}
		}
		slices.Sort(out)
		return out
	}
	bound := func(key, grantee, appointment, reg string, want int) map[string]any {
		return submitChange(t, w, sectest.Alice, widenReq(key, "grant", map[string]any{"governance_unit": root, "grantee": grantee,
			"appointment": appointment, "segments": []sdkauthz.Segment{orderSeg(region(reg))}}), want)
	}

	// Dan is an employee with Dave's account; a sales appointment (active) and a later one (planned)
	dan, link, sales, later := ids.New().String(), ids.New().String(), ids.New().String(), ids.New().String()
	require.NoError(t, emp.hire(ctx, dan, "active", 1))
	require.NoError(t, emp.link(ctx, link, dan, dave, "active", ids.New().String(), nil, 1))
	require.NoError(t, emp.appoint(ctx, sales, dan, "active", 1))
	require.NoError(t, emp.appoint(ctx, later, dan, "planned", 1))
	require.Eventually(t, func() bool { return factOf(t, admin, later).Version == 1 && factOf(t, admin, link).Version == 1 },
		15*time.Second, 100*time.Millisecond, "the facts applied")

	// made on the appointment: the account must be linked to its employee, the appointment planned or active
	east := bound("ap1", dave, sales, "east", 200)
	west := bound("ap2", dave, later, "west", 200)
	plain := submitChange(t, w, sectest.Alice, grantReq("ap3", root, dave, []sdkauthz.Segment{orderSeg(region("north"))}), 200)
	out := bound("ap4", carol, sales, "east", 400)
	assert.Contains(t, out["detail"], "not linked", "%v", out)
	out = bound("ap5", dave, ids.New().String(), "east", 400)
	assert.Contains(t, out["detail"], "no appointment", "%v", out)
	require.Eventually(t, func() bool { return slices.Equal(regions(dave), []string{"east", "north"}) }, 10*time.Second,
		200*time.Millisecond, "the active appointment's grant gives access, the planned one's not yet")

	// a transfer: the sales appointment ends, the later one begins; the grant bound to the old one is gone at once and
	// booked ended; the new appointment gives what was bound to it, nothing more
	require.NoError(t, emp.appoint(ctx, sales, dan, "ended", 2))
	require.NoError(t, emp.appoint(ctx, later, dan, "active", 2))
	require.Eventually(t, func() bool { return slices.Equal(regions(dave), []string{"north", "west"}) }, 10*time.Second,
		200*time.Millisecond, "the old appointment's grant left out, the new one's given")
	require.Eventually(t, func() bool { r := recordOf(t, admin, east["record"]); return r.State == "ended" }, 10*time.Second,
		100*time.Millisecond, "the closure books it")
	assert.Equal(t, "source_ended", recordOf(t, admin, east["record"]).EndReason)
	assert.Equal(t, "active", recordOf(t, admin, west["record"]).State)
	out = bound("ap6", dave, sales, "east", 400)
	assert.Contains(t, out["detail"], "ended", "an ended appointment is never bound again: %v", out)

	// a management holding on the appointment (protected: the owner confirms, no other admin), ended with it
	holding := protect(t, w, sectest.Alice, widenReq("ap7", "management_holding", map[string]any{"unit": root, "holder": dave,
		"appointment": later}))

	// the link ends: what Dave's account holds through Dan's appointments ends; the plain grant stays
	require.NoError(t, emp.link(ctx, link, dan, dave, "ended", "", nil, 2))
	require.Eventually(t, func() bool { return slices.Equal(regions(dave), []string{"north"}) }, 10*time.Second,
		200*time.Millisecond, "unlinked: nothing through the appointment")
	require.Eventually(t, func() bool {
		return recordOf(t, admin, west["record"]).State == "ended" && recordOf(t, admin, holding["record"]).State == "ended"
	}, 10*time.Second, 100*time.Millisecond, "the closure books the grant and the holding")
	assert.Equal(t, "source_ended", recordOf(t, admin, holding["record"]).EndReason)
	assert.Equal(t, "active", recordOf(t, admin, plain["record"]).State)
}
