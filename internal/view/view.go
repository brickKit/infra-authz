package view

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	core "github.com/brickKit/infra-authz/v3/internal/core"
	effectpoint "github.com/brickKit/infra-authz/v3/internal/effectpoint"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/grpcx"
	"github.com/brickKit/be-sdk-go/v3/projection"
	"github.com/brickKit/be-sdk-go/v3/records"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
)

// shardOf is a component's shard key in this step: one shard per component (step5-contracts), the component ID
// as a Key ("test/probe-go" -> "test.probe_go").
func shardOf(component string) string {
	return strings.NewReplacer("/", ".", "-", "_").Replace(component)
}

// stableID is a record identity fixed by its parts: a UUID with the version 7 and variant bits over SHA-256 bits.
func stableID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	b := sum[:16]
	b[6] = b[6]&0x0f | 0x70
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// definitionsOf reads a component's current accepted definitions: resource definitions by type, with the version.
type Defined struct {
	version    string
	Resources  map[string]map[string]any     `json:"-"` // type -> the resource definition's body
	Declared   map[string]*sdkauthz.Resource `json:"-"` // type -> the same as the SDK's declaration (the segment checks)
	digests    map[string]string             // type -> the resource definition's digest
	Operations map[string]bool               `json:"-"` // the operation keys its definitions declare
}

// relinquishFrom is the fixed relinquish segment's validity: from always (D82).
const relinquishFrom = "2000-01-01T00:00:00.000000Z"

// place adds a principal's segment in canonical form, with its source record and the definition it rests on.
func place(segsOf map[string][]any, principal string, s sdkauthz.Segment, source, component string, defs Defined) error {
	s.Source = source
	s.Definition, _ = json.Marshal(map[string]any{"owner_component": component, "kind": "resource",
		"key": s.ResourceType, "version": defs.version, "digest": defs.digests[s.ResourceType]})
	c, err := s.Canonical(s.ResourceType)
	if err != nil {
		return err
	}
	segsOf[principal] = append(segsOf[principal], c)
	return nil
}

// holders are the principals holding an active grant or management holding, each with the first such record (the
// source of its relinquish segment).
func holders(ctx context.Context, tx db.Tx, grants []core.Record) (map[string]string, error) {
	holdings, err := core.Active(ctx, tx, "management_holding")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	add := func(p, id string) {
		if cur, ok := out[p]; p != "" && (!ok || id < cur) {
			out[p] = id
		}
	}
	for _, g := range grants {
		var b core.GrantBody
		if err := json.Unmarshal(g.Body, &b); err != nil {
			return nil, err
		}
		add(b.Grantee, g.ID)
	}
	for _, h := range holdings {
		var b core.HoldingBody
		if err := json.Unmarshal(h.Body, &b); err != nil {
			return nil, err
		}
		add(b.Holder, h.ID)
	}
	return out, nil
}

// Usable: a segment of this component's resource types whose permission key is registered, not retired and still
// defined by the component (security 08: only those take part in an effective segment), and that fits the resource's
// current definition: a grant made before the resource gained a dimension lacks its atom and is never read as "all"
// on it (security 07's FX01); it waits for a narrowing or a renewal that names the dimension.
func (d Defined) Usable(s sdkauthz.Segment, reg core.Registry) bool {
	r, mine := d.Declared[s.ResourceType]
	return mine && d.Operations[s.Operation] && reg.Usable(s.Operation) && s.Check(r) == nil
}

func definitionsOf(ctx context.Context, tx db.Tx, component string) (Defined, bool, error) {
	d := Defined{Resources: map[string]map[string]any{}, Declared: map[string]*sdkauthz.Resource{}, digests: map[string]string{},
		Operations: map[string]bool{}}
	rows, err := tx.Query(ctx, `SELECT c.version, d.record_type, d.key, d.digest, d.record FROM authz_component c
		JOIN authz_definition_set s ON s.component = c.component AND s.version = c.version
		JOIN authz_definition d ON d.digest = ANY(s.digests)
		WHERE c.component = $1`, component)
	if err != nil {
		return d, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var rt, key, digest string
		var raw []byte
		if err := rows.Scan(&d.version, &rt, &key, &digest, &raw); err != nil {
			return d, false, err
		}
		if rt == "be.security.operation_definition" {
			d.Operations[key] = true
		}
		if rt != "be.security.resource_definition" {
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			return d, false, err
		}
		d.Resources[key], d.Declared[key], d.digests[key] = body, core.ResourceOf(body), digest
	}
	return d, d.version != "", rows.Err()
}

// How a view may be renewed, by its identity source's watermark age (security 03's renewal and closing).
type renewal int

const (
	renewFully    renewal = iota // no older than D_src_high
	renewReadOnly                // older, but no older than D_src_read: ordinary reads only (P8.11's read_only)
	renewNone                    // older still, no watermark, or the source not aligned: closed
)

// account is what a view says of a subject's account: disabled, and its security version (0: not known).
type account struct {
	disabled bool
	version  int64
}

// accountsOf judges the subjects' accounts in the identity source (P9.24) at D_src_read and says how the view may
// be renewed. A subject whose account is not provable (its events quarantined) is left out of the view: no access
// without evidence, and the others are not held back by it. One the source proves absent has no status to show.
func accountsOf(m *core.Base, ctx context.Context, tx db.Tx, principals []string) (map[string]account, renewal, []string, error) {
	asked := make(map[string][]string, len(principals))
	for _, p := range principals {
		asked[p] = []string{p} // an account's events list its principal as their subject
	}
	j, err := m.Accounts.JudgeMany(ctx, tx, asked, m.SrcRead)
	if err != nil {
		return nil, renewNone, nil, err
	}
	if j.Source != projection.Usable {
		return nil, renewNone, nil, nil
	}
	r := renewFully
	if !j.HasWatermark || j.Age > m.SrcHigh {
		r = renewReadOnly
	}
	out := map[string]account{}
	var unprovable []string
	for p, jd := range j.Records {
		switch jd.Verdict {
		case projection.Usable:
			var rec struct {
				Status          string `json:"status"`
				SecurityVersion int64  `json:"security_version"`
			}
			if err := json.Unmarshal(jd.Data, &rec); err != nil {
				return nil, renewNone, nil, fmt.Errorf("account %s: %w", p, err)
			}
			out[p] = account{disabled: rec.Status != "active", version: rec.SecurityVersion}
		case projection.ProvablyAbsent:
			out[p] = account{}
		default:
			unprovable = append(unprovable, p)
		}
	}
	return out, r, unprovable, nil
}

// view computes a component's shard from the committed records: canonical bytes and their digest (D76), and how the
// answer may renew it.
func view(m *core.Base, ctx context.Context, tx db.Tx, component string) (raw []byte, digest string, st core.State, ok bool,
	renew renewal, err error) {
	if st, err = core.ReadState(ctx, tx); err != nil {
		return
	}
	defs, ok, err := definitionsOf(ctx, tx, component)
	if err != nil || !ok {
		return nil, "", st, false, renewNone, err
	}
	grants, err := core.Active(ctx, tx, "grant")
	if err != nil {
		return
	}
	units, err := effectpoint.Units(m, ctx, tx)
	if err != nil {
		return
	}
	reg, err := core.RegistryNow(m)
	if err != nil {
		return
	}
	roles, err := core.Active(ctx, tx, "role_revision")
	if err != nil {
		return
	}
	activeRole := map[string]bool{}
	for _, r := range roles {
		activeRole[r.ID] = true
	}
	lims := core.NewLimits(units)
	disposed, err := effectpoint.ActiveDispositions(ctx, tx)
	if err != nil {
		return
	}
	segsOf := map[string][]any{}
	for _, g := range grants {
		var b core.GrantBody
		if err = json.Unmarshal(g.Body, &b); err != nil {
			return
		}
		if b.RoleRevision != "" && !activeRole[b.RoleRevision] {
			continue // its role revision is no longer effective: nothing (security 08)
		}
		// the effective segments (security 08): the grant's ∩ its governance unit's current limit, of keys registered,
		// not retired and still defined by their owner
		for _, s := range lims.OfFor(b.GovernanceUnit, b.Grantee).Cut(b.Segments, b.Grantee) {
			// a segment that meets a scope an active disposition suspends is left out whole (security 08)
			if !defs.Usable(s, reg) || effectpoint.Suspended(disposed[b.Grantee], s, b.Grantee) {
				continue
			}
			if err = place(segsOf, b.Grantee, s, g.ID, component, defs); err != nil {
				return
			}
		}
	}
	if component == core.ID { // D82: every holder may relinquish its own records; nobody grants it
		var firstOf map[string]string
		if firstOf, err = holders(ctx, tx, grants); err != nil {
			return
		}
		self := map[string]sdkauthz.Atom{core.Holder: {Kind: "self"}}
		for p, src := range firstOf {
			for _, s := range []sdkauthz.Segment{ // to see one's own records, and relinquish them
				{ResourceType: core.Records, Operation: core.OpRead, Atoms: self, ReadFields: []string{"body", "id", "record_type", "state"},
					Valid: sdkauthz.Window{From: relinquishFrom}},
				{ResourceType: core.Records, Operation: core.OpRelinquish, Atoms: self, Valid: sdkauthz.Window{From: relinquishFrom}},
			} {
				if !defs.Usable(s, reg) || effectpoint.Suspended(disposed[p], s, p) {
					continue
				}
				if err = place(segsOf, p, s, src, component, defs); err != nil {
					return
				}
			}
		}
	}
	principals := make([]string, 0, len(segsOf))
	for p := range segsOf {
		principals = append(principals, p)
	}
	accounts, renew, unprovable, err := accountsOf(m, ctx, tx, principals)
	if err != nil || renew == renewNone {
		return nil, "", st, true, renewNone, err
	}
	if len(unprovable) > 0 {
		m.RT.Logger.Warn("accounts whose status cannot be proven are left out of the view", "component", component,
			"accounts", len(unprovable))
	}
	subjects := map[string]any{}
	for p, segs := range segsOf {
		a, known := accounts[p]
		if !known {
			continue // not provable
		}
		set, serr := canon.SortedSet(segs)
		if serr != nil {
			err = serr
			return
		}
		entry := map[string]any{"segments": set, "accounts_disabled": a.disabled}
		if a.version > 0 {
			entry["security_version"] = a.version // P8.25: admission refuses an older token
		}
		subjects[p] = entry
	}
	types := make([]any, 0, len(defs.Resources))
	for t := range defs.Resources {
		types = append(types, t)
	}
	applicability, err := canon.SortedSet(types)
	if err != nil {
		return
	}
	shard := shardOf(component)
	rev := strconv.FormatInt(st.Revision, 10)
	raw, digest, err = records.Seal("be.security.view", map[string]any{
		"record_type": "be.security.view", "schema": "1.0", "deployment": m.Deployment, "authority": core.ID,
		"id":       stableID("be.security.view", m.Deployment, shard),
		"revision": map[string]any{"domain": core.ShardDomain + shard, "value": rev, "epoch": st.Epoch, "instance": st.Instance},
		"shard":    shard, "recovery_generation": map[string]any{"domain": "authz.recovery", "value": strconv.FormatInt(st.Recovery, 10)},
		"security_revisions": []any{map[string]any{"domain": core.SecurityDomain, "value": rev, "epoch": st.Epoch, "instance": st.Instance}},
		"applicability":      applicability, "subjects": subjects, "capabilities": []any{}})
	return raw, digest, st, true, renew, err
}

// Verify is ViewService.Verify (contract-infra-authz README): recomputed on the primary for every request, never
// cached; the held digest equal to the current one is unchanged, anything else gets the current view.
func Verify(m *core.Base, ctx context.Context, in *authzv3.VerifyRequest) (*authzv3.VerifyResponse, error) {
	if caller, _ := grpcx.Caller(ctx); caller != in.GetComponent() {
		return nil, errs.New(errs.ReasonPermissionDenied, "a component verifies only its own view")
	}
	var raw []byte
	var digest string
	var st core.State
	var ok bool
	var renew renewal
	err := m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		raw, digest, st, ok, renew, err = view(m, ctx, tx, in.GetComponent())
		return err
	}, db.Serializable())
	if err != nil {
		return nil, err
	}
	shard := shardOf(in.GetComponent())
	out := &authzv3.VerifyResponse{Nonce: in.GetNonce(), ComputedAt: canon.Time(time.Now()), Instance: st.Instance,
		RecoveryGeneration: &authzv3.RevisionRef{Domain: "authz.recovery", Value: strconv.FormatInt(st.Recovery, 10)}}
	readOnly := renew == renewReadOnly
	switch {
	case !ok, renew == renewNone: // no accepted definitions, or the identity source too old: nothing can be proven
		out.Shards = append(out.Shards, &authzv3.ShardAnswer{Shard: shard, Status: authzv3.ShardStatus_SHARD_STATUS_CLOSED})
	case heldDigest(in, shard) == digest:
		out.Shards = append(out.Shards, &authzv3.ShardAnswer{Shard: shard, Status: authzv3.ShardStatus_SHARD_STATUS_UNCHANGED,
			ReadOnly: readOnly})
	default:
		out.Shards = append(out.Shards, &authzv3.ShardAnswer{Shard: shard, Status: authzv3.ShardStatus_SHARD_STATUS_CHANGED,
			View: raw, Digest: digest, ReadOnly: readOnly})
	}
	return out, nil
}

func heldDigest(in *authzv3.VerifyRequest, shard string) string {
	for _, h := range in.GetHeld() {
		if h.GetShard() == shard {
			return h.GetDigest()
		}
	}
	return ""
}
