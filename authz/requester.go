package authz

import (
	"context"
	"encoding/json"
	"time"

	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/projection"
	"github.com/jackc/pgx/v5"
)

// eligibility sets the requester's eligibility (security 08, rows 8-12): its management standing as the security
// records stand (structural), and its account as the identity source proves it now (a change is a high-risk
// operation) and by the last applied facts, with whether those need a second person (security 03, row 21).
func (m *Module) eligibility(ctx context.Context, tx db.Tx, requester string, structural bool, f *facts) error {
	a, err := m.accountOf(ctx, tx, requester)
	if err != nil {
		return err
	}
	switch {
	case !structural || a.now == disproven:
		f.Eligible = disproven
	case a.now == proven:
		f.Eligible = proven
	default:
		f.Eligible, f.LastApplied, f.Quarantined, f.BeyondTight = unprovable, a.last, a.quarantined, a.beyondTight
		f.Basis = a.basis
	}
	return nil
}

// accountProof is what the identity source proves of an account: now (at D_src_high), and by the last applied facts
// (P9.34) when not now.
type accountProof struct {
	now         proof
	last        bool // active by the last applied facts
	quarantined bool // the source is fresh, the account is not provable: its subject is quarantined
	// beyondTight: the last applied facts need a second person (security 03): the watermark older than T_tight,
	// no watermark, or a stalled source
	beyondTight bool
	basis       map[string]any // the audit's "basis not proven latest" (security 03): the source as the judgement saw it
}

// accountOf proves the requester's account active: at D_src_high, and by the last applied facts.
func (m *Module) accountOf(ctx context.Context, tx db.Tx, principal string) (accountProof, error) {
	asked := map[string][]string{principal: {principal}}
	j, err := m.accounts.JudgeMany(ctx, tx, asked, m.srcHigh)
	if err != nil {
		return accountProof{}, err
	}
	var a accountProof
	if a.now, err = activeAccount(j.Records[principal]); err != nil || a.now != unprovable {
		return a, err
	}
	a.quarantined = j.Source == projection.Usable
	lj, err := m.accounts.JudgeApplied(ctx, tx, asked)
	if err != nil {
		return accountProof{}, err
	}
	l, err := activeAccount(lj.Records[principal])
	a.last = l == proven
	a.beyondTight = beyondTight(lj, m.tight)
	a.basis = map[string]any{"basis": "not_proven_latest", "source_state": lj.SourceState}
	if lj.HasWatermark {
		a.basis["watermark_age_seconds"] = int64(lj.Age.Seconds())
	}
	return a, err
}

// beyondTight: a judgement by the last applied facts needs a second person (security 03): the source's watermark
// older than T_tight, no watermark (its age unknown), or a stalled source (its facts may predate a rollback).
func beyondTight(j projection.Judgement, tight time.Duration) bool {
	return !j.HasWatermark || j.Age > tight || j.SourceState == projection.Stalled
}

// activeAccount reads one judged account: proven active, proven not (another status, or no account: nobody to be
// eligible), or not provable.
func activeAccount(jd projection.Judged) (proof, error) {
	switch jd.Verdict {
	case projection.Usable:
		var rec struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(jd.Data, &rec); err != nil {
			return unprovable, err
		}
		if rec.Status == "active" {
			return proven, nil
		}
		return disproven, nil
	case projection.ProvablyAbsent:
		return disproven, nil
	}
	return unprovable, nil
}

// adminsAfter proves whether an authorization admin stays available once a change ends the holdings in ended
// (security 08's last-admin invariant, rows 27-28): available is a person with an active admin holding outside
// ended — another holding of the same person counts — whose account the identity source proves active now. Proven:
// one such person; disproven: every remaining holding's person provably not available (or none left); otherwise not
// provable.
func (m *Module) adminsAfter(ctx context.Context, tx db.Tx, ended []string) (proof, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT body->>'holder' FROM authz_record WHERE state = 'active'
		AND record_type = 'management_holding' AND body->>'system_role' = 'authorization_admin' AND id::text <> ALL($1)`,
		nonNil(ended))
	if err != nil {
		return unprovable, err
	}
	holders, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(holders) == 0 {
		return disproven, err
	}
	result := disproven
	for _, h := range holders {
		a, err := m.accountOf(ctx, tx, h)
		if err != nil {
			return unprovable, err
		}
		switch a.now {
		case proven:
			return proven, nil
		case unprovable:
			result = unprovable
		}
	}
	return result, nil
}

// endedAdminHoldings are the authorization admin holdings a change that ends t ends: t itself, or the active ones
// in the unit t and below (the closure job ends them after it).
func endedAdminHoldings(ctx context.Context, tx db.Tx, units map[string]unitBody, t *target) ([]string, error) {
	switch t.Type {
	case "management_holding":
		return []string{t.ID}, nil
	case "management_unit":
		recs, err := active(ctx, tx, "management_holding")
		if err != nil {
			return nil, err
		}
		var out []string
		for _, r := range recs {
			var h holdingBody
			if err := json.Unmarshal(r.Body, &h); err != nil {
				return nil, err
			}
			if h.SystemRole != "authorization_admin" {
				continue
			}
			u := h.Unit
			for range len(units) + 1 {
				if sameUnit(units, u, t.ID) {
					out = append(out, r.ID)
					break
				}
				if u = units[u].Parent; u == "" {
					break
				}
			}
		}
		return out, nil
	}
	return nil, nil
}
