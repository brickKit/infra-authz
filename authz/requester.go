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
// operation) and by the last applied facts.
func (m *Module) eligibility(ctx context.Context, tx db.Tx, requester string, structural bool, f *facts) error {
	acct, last, quarantined, err := m.accountOf(ctx, tx, requester)
	if err != nil {
		return err
	}
	switch {
	case !structural || acct == disproven:
		f.Eligible = disproven
	case acct == proven:
		f.Eligible = proven
	default:
		f.Eligible, f.LastApplied, f.Quarantined = unprovable, last, quarantined
	}
	return nil
}

// accountOf proves the requester's account active: at D_src_high, and by the last applied facts (any age).
func (m *Module) accountOf(ctx context.Context, tx db.Tx, principal string) (now proof, last, quarantined bool, err error) {
	asked := map[string][]string{principal: {principal}}
	j, err := m.accounts.JudgeMany(ctx, tx, asked, m.srcHigh)
	if err != nil {
		return unprovable, false, false, err
	}
	active := func(jd projection.Judged) (proof, error) {
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
		case projection.ProvablyAbsent: // no account: nobody to be eligible
			return disproven, nil
		}
		return unprovable, nil
	}
	if now, err = active(j.Records[principal]); err != nil || now != unprovable {
		return now, now == proven, false, err
	}
	quarantined = j.Source == projection.Usable // the source is fresh, this account is not provable: quarantined
	lj, err := m.accounts.JudgeMany(ctx, tx, asked, 100*365*24*time.Hour)
	if err != nil {
		return unprovable, false, false, err
	}
	l, err := active(lj.Records[principal])
	return unprovable, l == proven, quarantined, err
}

// adminsBesides proves whether an authorization admin other than holder stays available (security 08, rows 27-28).
func (m *Module) adminsBesides(ctx context.Context, tx db.Tx, holder string) (proof, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT body->>'holder' FROM authz_record WHERE state = 'active'
		AND record_type = 'management_holding' AND body->>'system_role' = 'authorization_admin' AND body->>'holder' <> $1`, holder)
	if err != nil {
		return unprovable, err
	}
	others, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(others) == 0 {
		return disproven, err
	}
	result := disproven
	for _, o := range others {
		a, _, _, err := m.accountOf(ctx, tx, o)
		if err != nil {
			return unprovable, err
		}
		switch a {
		case proven:
			return proven, nil
		case unprovable:
			result = unprovable
		}
	}
	return result, nil
}
