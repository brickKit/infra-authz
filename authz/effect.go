package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/brickKit/be-sdk-go/v3/audit"
	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/jackc/pgx/v5"
)

// errRejected carries a final rejection out of the effect point's transaction so its key is bound in a second one.
type errRejected struct{ Reason, Detail string }

func (e *errRejected) Error() string { return e.Reason + ": " + e.Detail }

func reject(reason, detail string) error {
	return &errRejected{Reason: reason, Detail: detail}
}

// applied advances the security revision and writes the security change's audit record in the same transaction.
func (m *Module) applied(ctx context.Context, tx db.Tx, requester, direction, typ, id string) (int64, error) {
	if err := advance(ctx, tx); err != nil {
		return 0, err
	}
	var rev int64
	if err := tx.QueryRow(ctx, "SELECT security_revision FROM authz_state").Scan(&rev); err != nil {
		return 0, err
	}
	return rev, m.audited(ctx, tx, requester, direction, typ, id, fmt.Sprint(rev))
}

// audited writes a security change's audit record in its transaction; rev is the security revision it advanced to
// ("" for a neutral change, which advances none).
func (m *Module) audited(ctx context.Context, tx db.Tx, requester, direction, typ, id, rev string) error {
	changes := map[string]any{"direction": direction}
	if rev != "" {
		changes["security_revision"] = rev
	}
	_, err := m.rt.Audit.Write(ctx, tx, audit.Record{Category: audit.SecurityChange, Operation: OpChange,
		Outcome: audit.Succeeded, Actor: requester, Target: map[string]any{"type": typ, "id": id}, Changes: changes})
	return err
}

// within proves every candidate segment is contained in one of the unit's limit segments for its operation (security
// 07; no split along a dimension in this step). A root unit contains every well-formed segment.
func (m *Module) within(ctx context.Context, tx db.Tx, segs []sdkauthz.Segment, unit unitBody, grantee string) error {
	for _, s := range segs {
		r, err := m.resourceFor(ctx, tx, s.ResourceType)
		if err != nil {
			return err
		}
		if r == nil {
			reg, err := m.registry()
			if err != nil {
				return err
			}
			if reg.owner("resource_type", s.ResourceType) == "" {
				// no component of this deployment owns it (a typo, a component not deployed): nothing is on its way,
				// so a final rejection that binds the key (D77)
				return reject(errs.ReasonRequestInvalid, "resource type "+s.ResourceType+" is not registered in this deployment")
			}
			// its owner is ready before its definitions are accepted (P8.24): retryable, the key stays free (D77)
			return reject(errs.ReasonDefinitionPending, "resource type "+s.ResourceType+" is not defined yet")
		}
		if err := s.Check(r); err != nil {
			return reject(errs.ReasonRequestInvalid, err.Error())
		}
		if unit.Root {
			continue
		}
		if !slices.Contains(unit.GrantableOperations, s.Operation) {
			return reject(errs.ReasonContainmentNotProven, "operation "+s.Operation+" is not grantable in the unit")
		}
		var last *notContained
		ok := slices.ContainsFunc(unit.ManagedScope, func(l sdkauthz.Segment) bool {
			last = contained(s, l, grantee)
			return last == nil
		})
		if !ok {
			why := "no limit segment for " + s.Operation
			if last != nil {
				why = last.Error()
			}
			return reject(errs.ReasonContainmentNotProven, why)
		}
	}
	return nil
}

func (m *Module) units(ctx context.Context, tx db.Tx) (map[string]unitBody, error) {
	recs, err := active(ctx, tx, "management_unit")
	if err != nil {
		return nil, err
	}
	out := map[string]unitBody{}
	for _, r := range recs {
		var u unitBody
		if err := json.Unmarshal(r.Body, &u); err != nil {
			return nil, err
		}
		out[r.ID] = u
	}
	return out, nil
}

// holdingsOf returns the units a principal holds and whether one holding makes it an authorization admin.
func holdingsOf(ctx context.Context, tx db.Tx, principal string) ([]string, bool, error) {
	recs, err := active(ctx, tx, "management_holding")
	if err != nil {
		return nil, false, err
	}
	var units []string
	admin := false
	for _, r := range recs {
		var h holdingBody
		if err := json.Unmarshal(r.Body, &h); err != nil {
			return nil, false, err
		}
		if h.Holder == principal {
			units = append(units, h.Unit)
			admin = admin || h.SystemRole == "authorization_admin"
		}
	}
	return units, admin, nil
}

func roleTemplate(ctx context.Context, tx db.Tx, id string) ([]sdkauthz.Segment, error) {
	var body json.RawMessage
	err := tx.QueryRow(ctx, "SELECT body FROM authz_record WHERE id = $1 AND record_type = 'role_revision' AND state = 'active'",
		id).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, reject(errs.ReasonRequestInvalid, "no such active role revision")
	} else if err != nil {
		return nil, err
	}
	var r roleBody
	return r.SegmentsTemplate, json.Unmarshal(body, &r)
}

// resourceFor finds a resource type among the current accepted definitions of every component.
func (m *Module) resourceFor(ctx context.Context, tx db.Tx, typ string) (*sdkauthz.Resource, error) {
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT d.record FROM authz_component c
		JOIN authz_definition_set s ON s.component = c.component AND s.version = c.version
		JOIN authz_definition d ON d.digest = ANY(s.digests)
		WHERE d.record_type = 'be.security.resource_definition' AND d.key = $1`, typ).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	return resourceOf(body), nil
}

// numbersAsText makes a decoded request encodable canonically: numbers as text (no floating point), no nulls.
func numbersAsText(v any) any {
	switch x := v.(type) {
	case float64:
		return fmt.Sprint(x)
	case []any:
		out := x[:0]
		for _, e := range x {
			if e != nil {
				out = append(out, numbersAsText(e))
			}
		}
		return out
	case map[string]any:
		for k, e := range x {
			if e == nil {
				delete(x, k)
			} else {
				x[k] = numbersAsText(e)
			}
		}
	}
	return v
}
