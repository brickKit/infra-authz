package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/evidence"
	"github.com/jackc/pgx/v5"
)

// The replay of this member's evidence in a full recovery's step 6 (assembly protocol 15, 6.3; be-protocol
// P12.19-P12.21): a tightening or a widening the restored database does not reflect goes through the effect point
// again with the request the evidence recorded (its requester, change key, target, candidate, effective time), so the
// records, the security revision, the closures and the audit are written as for the change itself. The business
// preconditions are not decided again (the requester's eligibility, containment, budgets, confirmations, a pending
// recovery, a member switch, a revision moved since): they held when the change was made, and the replay's
// intermediate states are no real moment. The record's state still decides (a record ended since stays ended); a new
// record keeps the identity the evidence names; the last admin is judged after the whole replay (6.5).

// Replays registers the replay of both categories (evidence.Replayer).
func (m *Module) Replays(r *evidence.Replays) error {
	r.Add("security_tightening", m.replay)
	r.Add("security_widening", m.replay)
	return nil
}

// replayFacts sets aside the business preconditions of a replayed change.
func replayFacts(f facts) facts {
	f.Eligible, f.Quarantined, f.LastApplied, f.BeyondTight = proven, false, false, false
	f.Contained, f.OverBudget, f.ConfirmersProvable = true, false, true
	f.NeedsConfirmation, f.TightenNeedsConfirmation = false, false
	f.RecoveryPending, f.MemberSwitch, f.RevisionsChanged, f.FromRevision = false, false, false, true
	f.AdminsAfter = proven
	return f
}

func (m *Module) replay(ctx context.Context, tx db.Tx, rec evidence.Replayed) error {
	requester, _ := rec.Change["requested_by"].(string)
	key, _ := rec.Change["change_key"].(string)
	if requester == "" || key == "" {
		return errors.New("the record carries no requester or change key")
	}
	req := request{ChangeKey: key}
	req.Direction, _ = rec.Change["direction"].(string)
	req.Termination, _ = rec.Change["termination"].(string)
	req.Target, _ = rec.Change["target"].(string)
	req.EffectiveFrom, _ = rec.Change["effective_from"].(string)
	if c, ok := rec.Change["candidate"]; ok {
		raw, err := json.Marshal(c)
		if err != nil {
			return err
		}
		req.Candidate = raw
		var c candidateOf
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
		req.CandidateDigest = candidateDigest(c.RecordType, raw) // the digest is of the content (its canonical form)
	} else if req.Direction == Widen {
		return errors.New("a widening recorded without its candidate (before 3.0.29): for review")
	}
	if req.Target != "" { // the record the change acts on must still exist
		var one int
		err := tx.QueryRow(ctx, "SELECT 1 FROM authz_record WHERE id = $1", req.Target).Scan(&one)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("record %s: %w", req.Target, evidence.ErrDangling)
		}
		if err != nil {
			return err
		}
	}
	digest, err := requestDigest(requester, req)
	if err != nil {
		return err
	}
	e := entry{namespace: requester, key: key, digest: digest, requester: requester, trigger: ByUser, req: req,
		replay: rec.Object.ID}
	res, v, err := m.effect(ctx, tx, e)
	if err != nil {
		return err
	}
	switch {
	case res.Outcome == "applied", v.Row == 1: // applied now, or its result bound already (the change took place)
		return nil
	case res.Outcome == "rejected" && req.Direction == Tighten && req.Target != "":
		var state string
		if err := tx.QueryRow(ctx, "SELECT state FROM authz_record WHERE id = $1", req.Target).Scan(&state); err != nil {
			return err
		}
		if state == "ended" { // the record ended since: nothing left to tighten
			return nil
		}
	}
	return fmt.Errorf("the replay did not apply: %s %s (row %d)", res.Outcome, res.Detail, v.Row)
}
