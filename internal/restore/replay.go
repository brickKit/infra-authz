package restore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	core "github.com/brickKit/infra-authz/v3/internal/core"
	effectpoint "github.com/brickKit/infra-authz/v3/internal/effectpoint"

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

func Replay(m *core.Base, ctx context.Context, tx db.Tx, rec evidence.Replayed) error {
	requester, _ := rec.Change["requested_by"].(string)
	key, _ := rec.Change["change_key"].(string)
	if requester == "" || key == "" {
		return errors.New("the record carries no requester or change key")
	}
	req := effectpoint.Request{ChangeKey: key}
	req.Direction, _ = rec.Change["direction"].(string)
	if rel, ok := rec.Change["release"].(map[string]any); ok { // a disposition's release (T13b)
		in, err := replayedRelease(ctx, tx, rel)
		if err != nil {
			return err
		}
		req.Release = in
	}
	req.Termination, _ = rec.Change["termination"].(string)
	req.Target, _ = rec.Change["target"].(string)
	req.EffectiveFrom, _ = rec.Change["effective_from"].(string)
	if c, ok := rec.Change["candidate"]; ok {
		raw, err := json.Marshal(c)
		if err != nil {
			return err
		}
		req.Candidate = raw
		var c effectpoint.CandidateOf
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
		req.CandidateDigest = effectpoint.CandidateDigest(c.RecordType, raw) // the digest is of the content (its canonical form)
	} else if req.Direction == core.Widen && req.Release == nil {
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
	digest, err := effectpoint.RequestDigest(requester, req)
	if err != nil {
		return err
	}
	e := effectpoint.Entry{Namespace: requester, Key: key, Digest: digest, Requester: requester, Trigger: core.ByUser, Req: req,
		Replay: rec.Object.ID}
	res, v, err := effectpoint.Effect(m, ctx, tx, e)
	if err != nil {
		return err
	}
	switch {
	case res.Outcome == "applied", v.Row == 1: // applied now, or its result bound already (the change took place)
		return nil
	case res.Outcome == "rejected" && req.Direction == core.Tighten && req.Target != "":
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

// replayedRelease is a recorded release as the effect point takes it again. An identity-side release is matched by
// the signals it names, not by the disposition's identity: a full recovery derives the disposition again from the
// replayed account status, under another identity (security 08, "身份侧处置的派生"). While a signal it names is in no
// active identity-side disposition (its freeze not applied yet) it is deferred: asked again after 6.4, still missing
// for review. The disposition's revision is the one it has now: the release's revision and confirmations were checked
// when it was made.
func replayedRelease(ctx context.Context, tx db.Tx, rel map[string]any) (*effectpoint.ReleaseIn, error) {
	in := &effectpoint.ReleaseIn{}
	in.Disposition, _ = rel["disposition"].(string)
	if refs, ok := rel["signal_refs"].([]any); ok {
		for _, r := range refs {
			if s, ok := r.(string); ok {
				in.SignalRefs = append(in.SignalRefs, s)
			}
		}
	}
	if len(in.SignalRefs) > 0 {
		err := tx.QueryRow(ctx, `SELECT id::text FROM authz_disposition WHERE state = 'active' AND origin = 'identity_side'
			AND signal_ref @> $1::text[]`, in.SignalRefs).Scan(&in.Disposition)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("no active identity-side disposition holds the signals %v yet: %w", in.SignalRefs,
				evidence.ErrDeferred)
		}
		if err != nil {
			return nil, err
		}
	}
	var revision int64
	err := tx.QueryRow(ctx, "SELECT revision FROM authz_disposition WHERE id::text = $1", in.Disposition).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("disposition %s: %w", in.Disposition, evidence.ErrDangling)
	}
	if err != nil {
		return nil, err
	}
	in.Revision = &effectpoint.RevisionRef{Domain: effectpoint.DispositionDomain, Value: strconv.FormatInt(revision, 10)}
	return in, nil
}
