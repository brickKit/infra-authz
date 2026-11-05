package authz

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/brickKit/be-sdk-go/v3/audit"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/evidence"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/jackc/pgx/v5"
)

// This member's part of a full recovery's step 6 after the replay (assembly protocol 15, 6.4-6.5; A142), the
// contract's RecoveryService, for the recovery tool only:
//   - Sources (6.4): whether the replay of the sources is applied: the watermark is no older than a moment taken
//     after the replay (be-protocol P9.35);
//   - ReplayDeferred (6.5): an intent-only tightening of this member, executed on the final state; one that leaves no
//     authorization admin provably available where one was is not executed, its subject closed for review;
//   - Check (6.5): every record judged against its sources as a closure would (the closure jobs do not run while the
//     recovery replays), the subjects under review closed unless authorization admins, the admins judged last.
// Separation of duties has no declared static exclusion in this version: nothing to check there.

// RecoveryTool is the recovery tool's service identity (be-protocol P12.19), the only caller of RecoveryService.
const RecoveryTool = "ops/recover"

// Outcomes of ReplayDeferred besides the SDK's (reflected, applied, dangling).
const replayForReview = "for_review"

// originRecoveryReview is the disposition that closes a subject under review (security 09a).
const originRecoveryReview = "recovery_review"

// Sources answers whether the identity source's replay is applied (6.4).
func (m *Module) Sources(ctx context.Context, in *authzv3.SourcesRequest) (*authzv3.SourcesResponse, error) {
	var asOf time.Time
	if in.GetSince() != "" {
		t, err := time.Parse(time.RFC3339Nano, in.GetSince())
		if err != nil {
			return nil, errs.New(errs.ReasonRequestInvalid, "since is the as_of of a first answer")
		}
		asOf = t
	}
	src := &authzv3.SourceState{Component: m.accounts.Source, Stream: m.accounts.Stream.Name}
	err := m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		if asOf.IsZero() { // the moment on this member's primary clock, the clock of the watermark (P9.35)
			if err := tx.QueryRow(ctx, "SELECT now()").Scan(&asOf); err != nil {
				return err
			}
		}
		j, err := m.accounts.JudgeApplied(ctx, tx, map[string][]string{})
		if err != nil {
			return err
		}
		src.State = j.SourceState
		src.Applied, err = m.accounts.NoOlderThan(ctx, tx, asOf)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !src.Applied {
		m.accounts.PullSoon() // a pull recorded after the moment: its echo comes after the source's replay
	}
	return &authzv3.SourcesResponse{AsOf: asOf.UTC().Format(time.RFC3339Nano), Sources: []*authzv3.SourceState{src},
		AllApplied: src.Applied}, nil
}

var errForReview = errors.New("no authorization admin would be provably available")

// ReplayDeferred executes an intent-only tightening on the final state (6.5): reflected or dangling as any replay; one
// that ends authorization admin holdings (the holding itself, or the unit above them) and leaves no admin provably
// available is not executed, and the holders of those holdings are closed for review.
func (m *Module) ReplayDeferred(ctx context.Context, in *authzv3.ReplayDeferredRequest) (*authzv3.ReplayDeferredResponse, error) {
	r, err := evidence.ParseReplayed(in.GetRecord(), ID)
	if err != nil {
		return nil, errs.New(errs.ReasonRequestInvalid, err.Error())
	}
	if r.Category != "security_tightening" || r.Phase != "intent" {
		return nil, errs.New(errs.ReasonRequestInvalid, "only an intent-only tightening is deferred to 6.5")
	}
	out := &authzv3.ReplayDeferredResponse{}
	var holders []string // of the admin holdings it would end
	err = m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		holders = nil
		done, err := evidence.ReplayTx(ctx, tx, r, func(ctx context.Context, tx db.Tx, r evidence.Replayed) error {
			var err error
			if holders, err = m.adminHoldersEnded(ctx, tx, r); err != nil {
				return err
			}
			if err := m.replay(ctx, tx, r); err != nil {
				return err
			}
			if len(holders) == 0 {
				return nil
			}
			after, err := m.adminsAfter(ctx, tx, nil)
			if err != nil {
				return err
			}
			if after == disproven {
				return errForReview
			}
			return nil
		})
		switch {
		case err != nil:
			return err
		case done:
			out.Outcome = evidence.AlreadyReflected
		default:
			out.Outcome = evidence.Applied
		}
		return nil
	})
	switch {
	case errors.Is(err, evidence.ErrDangling):
		out.Outcome, out.Detail, err = evidence.Dangling, err.Error(), nil // rolled back: nothing written
	case errors.Is(err, errForReview):
		out.Outcome, out.Detail = replayForReview, err.Error()
		err = m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
			for _, h := range holders {
				if _, err := m.closeForReview(ctx, tx, h, in.GetRecovery(), r.ID); err != nil {
					return err
				}
			}
			return nil
		})
	}
	if err != nil {
		return nil, err
	}
	m.rt.Logger.Warn("a deferred intent-only tightening replayed", "event", "evidence_replayed_deferred", "id", r.ID,
		"outcome", out.Outcome, "recovery", in.GetRecovery())
	return out, nil
}

// adminHoldersEnded are the holders of the authorization admin holdings a tightening's target would end (security
// 08's last admin: the holding itself, or the active ones in the unit and below); none for any other target.
func (m *Module) adminHoldersEnded(ctx context.Context, tx db.Tx, r evidence.Replayed) ([]string, error) {
	id, _ := r.Change["target"].(string)
	t, err := lockTarget(ctx, tx, id)
	if err != nil || t == nil {
		return nil, err
	}
	units, err := m.units(ctx, tx)
	if err != nil {
		return nil, err
	}
	if ok, err := affectsAdmins(ctx, tx, units, t); err != nil || !ok {
		return nil, err
	}
	ended, err := endedAdminHoldings(ctx, tx, units, t)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT body->>'holder' FROM authz_record WHERE id::text = ANY($1)
		AND body->>'system_role' = 'authorization_admin' ORDER BY 1`, nonNil(ended))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// closeForReview closes a subject with a recovery_review disposition, once (an active one stays the one).
func (m *Module) closeForReview(ctx context.Context, tx db.Tx, subject, recovery, ref string) (bool, error) {
	var open bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM authz_disposition WHERE subject = $1 AND origin = $2
		AND state = 'active')`, subject, originRecoveryReview).Scan(&open); err != nil || open {
		return open, err
	}
	id, held, err := m.globalDisposition(ctx, tx, subject, originRecoveryReview, nil,
		ID+":recovery_review:"+recovery+":"+ref)
	if err != nil || id == "" {
		return false, err
	}
	m.rt.Logger.Warn("a full recovery closed a subject for review", "subject", subject, "disposition", id, "held", held,
		"recovery", recovery)
	_, err = m.rt.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: OpDispose,
		Outcome: audit.Succeeded, Actor: ID, Target: map[string]any{"type": dispositionType, "id": id},
		Changes: map[string]any{"origin": originRecoveryReview, "recovery": recovery, "ref": ref, "held": held}})
	return true, err
}

// Check runs the invariant check on the final state (6.5), under the deployment's guard.
func (m *Module) Check(ctx context.Context, in *authzv3.CheckRequest) (*authzv3.CheckResponse, error) {
	for _, s := range in.GetReviewSubjects() {
		if !uuidText.MatchString(s) {
			return nil, errs.New(errs.ReasonRequestInvalid, "a review subject is a principal: "+s)
		}
	}
	out := &authzv3.CheckResponse{}
	err := m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		*out = authzv3.CheckResponse{}
		if _, err := tx.Exec(ctx, "SELECT 1 FROM authz_state FOR UPDATE"); err != nil {
			return err
		}
		ended, unprovable, err := m.accountsEnded(ctx, tx)
		if err != nil || len(unprovable) > 0 {
			out.Unprovable = unprovable
			return err
		}
		if err := m.keepAllBooks(ctx, tx, ended, out); err != nil {
			return err
		}
		for _, s := range in.GetReviewSubjects() {
			admin, err := adminHoldingsOf(ctx, tx, s)
			if err != nil {
				return err
			}
			if len(admin) > 0 { // an authorization admin stays open (protocol 15, 6.2)
				out.AdminsNotClosed = append(out.AdminsNotClosed, s)
				continue
			}
			if _, err := m.closeForReview(ctx, tx, s, in.GetRecovery(), "review"); err != nil {
				return err
			}
			out.Closed = append(out.Closed, s)
		}
		if err := m.judgeAdmins(ctx, tx); err != nil {
			return err
		}
		out.AdminState, err = adminState(ctx, tx)
		return err
	})
	if err != nil {
		return nil, err
	}
	m.rt.Logger.Warn("a full recovery's invariant check", "event", "recovery_check", "recovery", in.GetRecovery(),
		"admin_state", out.GetAdminState(), "ended", out.GetEnded(), "held", out.GetHeld(), "review", out.GetReview(),
		"closed", len(out.GetClosed()), "unprovable", len(out.GetUnprovable()))
	return out, nil
}

// accountsEnded proves, for every person of an effective or held grant or holding, whether the identity source
// shows the account ended; the ones it cannot prove now are listed (the check then judges nothing).
func (m *Module) accountsEnded(ctx context.Context, tx db.Tx) (map[string]bool, []string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT coalesce(body->>'grantee', body->>'holder') FROM authz_record
		WHERE state IN ('active', 'held') AND record_type IN ('grant', 'management_holding')
			AND coalesce(body->>'grantee', body->>'holder', '') <> '' ORDER BY 1`)
	if err != nil {
		return nil, nil, err
	}
	people, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, nil, err
	}
	ended, unprovable := map[string]bool{}, []string{}
	for _, p := range people {
		e, provable, err := m.accountEnded(ctx, tx, p)
		if err != nil {
			return nil, nil, err
		}
		if !provable {
			unprovable = append(unprovable, p)
			continue
		}
		ended[p] = e
	}
	return ended, unprovable, nil
}

// keepAllBooks judges every effective or held record against its sources (the closure's table): the units first
// until none moves (a unit's limit follows its parent's), then the holdings and the grants; the moves are counted.
func (m *Module) keepAllBooks(ctx context.Context, tx db.Tx, ended map[string]bool, out *authzv3.CheckResponse) error {
	world := func() (sources, error) {
		w, err := m.world(ctx, tx)
		w.ended = ended
		return w, err
	}
	keep := func(w sources, id string) (moved bool, err error) {
		before, beforeReview, err := bookOf(ctx, tx, id)
		if err != nil {
			return false, err
		}
		if err := m.keepBooks(ctx, tx, w, id, false); err != nil {
			return false, err
		}
		after, afterReview, err := bookOf(ctx, tx, id)
		if err != nil {
			return false, err
		}
		switch {
		case after != before && after == "ended":
			out.Ended++
		case after != before && after == "held":
			out.Held++
		case afterReview && !beforeReview:
			out.Review++
		}
		return after != before, nil
	}
	for moved := true; moved; {
		moved = false
		w, err := world()
		if err != nil {
			return err
		}
		units, err := recordsOf(ctx, tx, "management_unit")
		if err != nil {
			return err
		}
		for _, id := range units {
			mv, err := keep(w, id)
			if err != nil {
				return err
			}
			if mv { // the limits below it moved: judge the units again on the new world
				moved = true
				break
			}
		}
	}
	w, err := world()
	if err != nil {
		return err
	}
	for _, typ := range []string{"management_holding", "grant"} {
		ids, err := recordsOf(ctx, tx, typ)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := keep(w, id); err != nil {
				return err
			}
		}
	}
	return nil
}

// recordsOf are the effective or held records of a type, in a fixed order.
func recordsOf(ctx context.Context, tx db.Tx, recType string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT id::text FROM authz_record WHERE record_type = $1 AND state IN ('active', 'held')
		ORDER BY created_at, id`, recType)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// bookOf is a record's state and review flag.
func bookOf(ctx context.Context, tx db.Tx, id string) (string, bool, error) {
	var state string
	var review bool
	err := tx.QueryRow(ctx, "SELECT state, review FROM authz_record WHERE id = $1", id).Scan(&state, &review)
	if err != nil {
		return "", false, fmt.Errorf("record %s: %w", id, err)
	}
	return state, review, nil
}
