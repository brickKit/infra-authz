package effectpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/work"
	"github.com/jackc/pgx/v5"
)

// The member's own entries to the effect point (security 08): a saved record's job enters under a key derived from
// the record, its state revision and the trigger, in this member's namespace. This step has the scheduled widening
// due (T4d); a confirmation complete (T5) and an automatic restore (T4g) enter the same way.

// JobDue is the timed work item of a saved record (protocol 01, P7.24: enqueued with its run time).
const JobDue = "infra.authz.due"

// Trigger kinds of a derived key, and the state each starts from (security 08, "状态迁移"): a scheduled record due,
// a held (uncomputable) record whose sources can be computed again (the closure job registers it).
const (
	TriggerScheduled = "scheduled"
	TriggerRestore   = "restore"
	triggerConfirmed = "confirmed" // a saved widening whose confirmations are complete (T5c)
)

// MaxProcessingWait is how long a job waits on "processing" before it goes to an operator (security 08's parameter
// table: 24 hours).
const MaxProcessingWait = 24 * time.Hour

// firing is a job's argument: the record and the state revision it was registered for.
type firing struct {
	Record        string `json:"record"`
	StateRevision int64  `json:"state_revision"`
	Trigger       string `json:"trigger"`
}

// key is the derived key <record>:<state revision>:<trigger>: a record that moves on and comes back gets a new one,
// so a second entry is never answered by the first one's binding (CP55, CP81).
func (a firing) key() string {
	return a.Record + ":" + strconv.FormatInt(a.StateRevision, 10) + ":" + a.Trigger
}

// from is the state this trigger starts from.
func (a firing) from() string {
	switch a.Trigger {
	case TriggerScheduled:
		return "scheduled"
	case TriggerRestore:
		return "held"
	case triggerConfirmed:
		return "awaiting_confirmation"
	}
	return ""
}

func (a firing) digest() string {
	d, _ := canon.Digest("be.security.change_request", 1, map[string]any{"target": a.Record,
		"expected_state_revision": strconv.FormatInt(a.StateRevision, 10), "trigger": core.ByJob, "kind": a.Trigger})
	return d
}

var ErrProcessing = errors.New("the effect point answered processing")

// Due runs one saved record's entry. Processing is a business wait (security 08: retry_wait, the attempt not
// counted); a void job ends without changing anything (row 3); applied and a final rejection bind the derived key.
func Due(m *core.Base, ctx context.Context, r *work.Run) error {
	var a firing
	if err := json.Unmarshal(r.Args, &a); err != nil || a.from() == "" {
		return work.Permanent(fmt.Errorf("not a saved record's job: %s", r.Args))
	}
	direction := core.Widen
	if a.Trigger == TriggerRestore {
		direction = core.RestoreUncomputable
	}
	e := Entry{Namespace: core.ID, Key: a.key(), Digest: a.digest(), Trigger: core.ByJob, job: &a, Req: Request{Direction: direction}}
	var res ChangeResult
	err := r.Complete(ctx, func(ctx context.Context, tx db.Tx) error {
		err := tx.QueryRow(ctx, "SELECT requested_by FROM authz_record WHERE id = $1", a.Record).Scan(&e.Requester)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // no such record: nothing to do
		}
		if err != nil {
			return err
		}
		if res, _, err = Effect(m, ctx, tx, e); err == nil && res.Outcome == "processing" {
			return ErrProcessing
		}
		return err
	})
	if errors.Is(err, ErrProcessing) {
		return work.Wait(fmt.Errorf("%w: %s %s", ErrProcessing, res.Reason, res.Detail))
	}
	if err != nil {
		return err
	}
	Denied(m, ctx, e, res)
	return nil
}
