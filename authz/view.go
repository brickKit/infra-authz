package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

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

// state is the member's row and the database epoch, read in the view's transaction.
type state struct {
	recovery, revision int64
	instance, epoch    string
}

func readState(ctx context.Context, tx db.Tx) (state, error) {
	var s state
	if err := tx.QueryRow(ctx, "SELECT recovery_generation, security_revision, instance FROM authz_state").
		Scan(&s.recovery, &s.revision, &s.instance); err != nil {
		return s, err
	}
	var g, t int64
	if err := tx.QueryRow(ctx, "SELECT generation, timeline FROM be_current_db_epoch()").Scan(&g, &t); err != nil {
		return s, err
	}
	s.epoch = strconv.FormatInt(g, 10) + "." + strconv.FormatInt(t, 10)
	return s, nil
}

// definitionsOf reads a component's current accepted definitions: resource definitions by type, with the version.
type defined struct {
	version    string
	resources  map[string]map[string]any     // type -> the resource definition's body
	declared   map[string]*sdkauthz.Resource // type -> the same as the SDK's declaration (the segment checks)
	digests    map[string]string             // type -> the resource definition's digest
	operations map[string]bool               // the operation keys its definitions declare
}

// relinquishFrom is the fixed relinquish segment's validity: from always (D82).
const relinquishFrom = "2000-01-01T00:00:00.000000Z"

// place adds a principal's segment in canonical form, with its source record and the definition it rests on.
func place(segsOf map[string][]any, principal string, s sdkauthz.Segment, source, component string, defs defined) error {
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
func holders(ctx context.Context, tx db.Tx, grants []record) (map[string]string, error) {
	holdings, err := active(ctx, tx, "management_holding")
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
		var b grantBody
		if err := json.Unmarshal(g.Body, &b); err != nil {
			return nil, err
		}
		add(b.Grantee, g.ID)
	}
	for _, h := range holdings {
		var b holdingBody
		if err := json.Unmarshal(h.Body, &b); err != nil {
			return nil, err
		}
		add(b.Holder, h.ID)
	}
	return out, nil
}

// usable: a segment of this component's resource types whose permission key is registered, not retired and still
// defined by the component (security 08: only those take part in an effective segment), and that fits the resource's
// current definition: a grant made before the resource gained a dimension lacks its atom and is never read as "all"
// on it (security 07's FX01); it waits for a narrowing or a renewal that names the dimension.
func (d defined) usable(s sdkauthz.Segment, reg registry) bool {
	r, mine := d.declared[s.ResourceType]
	return mine && d.operations[s.Operation] && reg.usable(s.Operation) && s.Check(r) == nil
}

func definitionsOf(ctx context.Context, tx db.Tx, component string) (defined, bool, error) {
	d := defined{resources: map[string]map[string]any{}, declared: map[string]*sdkauthz.Resource{}, digests: map[string]string{},
		operations: map[string]bool{}}
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
			d.operations[key] = true
		}
		if rt != "be.security.resource_definition" {
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			return d, false, err
		}
		d.resources[key], d.declared[key], d.digests[key] = body, resourceOf(body), digest
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
func (m *Module) accountsOf(ctx context.Context, tx db.Tx, principals []string) (map[string]account, renewal, []string, error) {
	asked := make(map[string][]string, len(principals))
	for _, p := range principals {
		asked[p] = []string{p} // an account's events list its principal as their subject
	}
	j, err := m.accounts.JudgeMany(ctx, tx, asked, m.srcRead)
	if err != nil {
		return nil, renewNone, nil, err
	}
	if j.Source != projection.Usable {
		return nil, renewNone, nil, nil
	}
	r := renewFully
	if !j.HasWatermark || j.Age > m.srcHigh {
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
func (m *Module) view(ctx context.Context, tx db.Tx, component string) (raw []byte, digest string, st state, ok bool,
	renew renewal, err error) {
	if st, err = readState(ctx, tx); err != nil {
		return
	}
	defs, ok, err := definitionsOf(ctx, tx, component)
	if err != nil || !ok {
		return nil, "", st, false, renewNone, err
	}
	grants, err := active(ctx, tx, "grant")
	if err != nil {
		return
	}
	units, err := m.units(ctx, tx)
	if err != nil {
		return
	}
	reg, err := m.registry()
	if err != nil {
		return
	}
	roles, err := active(ctx, tx, "role_revision")
	if err != nil {
		return
	}
	activeRole := map[string]bool{}
	for _, r := range roles {
		activeRole[r.ID] = true
	}
	lims := newLimits(units)
	disposed, err := activeDispositions(ctx, tx)
	if err != nil {
		return
	}
	segsOf := map[string][]any{}
	for _, g := range grants {
		var b grantBody
		if err = json.Unmarshal(g.Body, &b); err != nil {
			return
		}
		if b.RoleRevision != "" && !activeRole[b.RoleRevision] {
			continue // its role revision is no longer effective: nothing (security 08)
		}
		// the effective segments (security 08): the grant's ∩ its governance unit's current limit, of keys registered,
		// not retired and still defined by their owner
		for _, s := range lims.ofFor(b.GovernanceUnit, b.Grantee).cut(b.Segments, b.Grantee) {
			// a segment that meets a scope an active disposition suspends is left out whole (security 08)
			if !defs.usable(s, reg) || suspended(disposed[b.Grantee], s, b.Grantee) {
				continue
			}
			if err = place(segsOf, b.Grantee, s, g.ID, component, defs); err != nil {
				return
			}
		}
	}
	if component == ID { // D82: every holder may relinquish its own records; nobody grants it
		var firstOf map[string]string
		if firstOf, err = holders(ctx, tx, grants); err != nil {
			return
		}
		self := map[string]sdkauthz.Atom{Holder: {Kind: "self"}}
		for p, src := range firstOf {
			for _, s := range []sdkauthz.Segment{ // to see one's own records, and relinquish them
				{ResourceType: Records, Operation: OpRead, Atoms: self, ReadFields: []string{"body", "id", "record_type", "state"},
					Valid: sdkauthz.Window{From: relinquishFrom}},
				{ResourceType: Records, Operation: OpRelinquish, Atoms: self, Valid: sdkauthz.Window{From: relinquishFrom}},
			} {
				if !defs.usable(s, reg) || suspended(disposed[p], s, p) {
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
	accounts, renew, unprovable, err := m.accountsOf(ctx, tx, principals)
	if err != nil || renew == renewNone {
		return nil, "", st, true, renewNone, err
	}
	if len(unprovable) > 0 {
		m.rt.Logger.Warn("accounts whose status cannot be proven are left out of the view", "component", component,
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
	types := make([]any, 0, len(defs.resources))
	for t := range defs.resources {
		types = append(types, t)
	}
	applicability, err := canon.SortedSet(types)
	if err != nil {
		return
	}
	shard := shardOf(component)
	rev := strconv.FormatInt(st.revision, 10)
	raw, digest, err = records.Seal("be.security.view", map[string]any{
		"record_type": "be.security.view", "schema": "1.0", "deployment": m.deployment, "authority": ID,
		"id":       stableID("be.security.view", m.deployment, shard),
		"revision": map[string]any{"domain": ShardDomain + shard, "value": rev, "epoch": st.epoch, "instance": st.instance},
		"shard":    shard, "recovery_generation": map[string]any{"domain": "authz.recovery", "value": strconv.FormatInt(st.recovery, 10)},
		"security_revisions": []any{map[string]any{"domain": SecurityDomain, "value": rev, "epoch": st.epoch, "instance": st.instance}},
		"applicability":      applicability, "subjects": subjects, "capabilities": []any{}})
	return raw, digest, st, true, renew, err
}

// Verify is ViewService.Verify (contract-infra-authz README): recomputed on the primary for every request, never
// cached; the held digest equal to the current one is unchanged, anything else gets the current view.
func (m *Module) Verify(ctx context.Context, in *authzv3.VerifyRequest) (*authzv3.VerifyResponse, error) {
	if caller, _ := grpcx.Caller(ctx); caller != in.GetComponent() {
		return nil, errs.New(errs.ReasonPermissionDenied, "a component verifies only its own view")
	}
	var raw []byte
	var digest string
	var st state
	var ok bool
	var renew renewal
	err := m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		raw, digest, st, ok, renew, err = m.view(ctx, tx, in.GetComponent())
		return err
	}, db.Serializable())
	if err != nil {
		return nil, err
	}
	shard := shardOf(in.GetComponent())
	out := &authzv3.VerifyResponse{Nonce: in.GetNonce(), ComputedAt: canon.Time(time.Now()), Instance: st.instance,
		RecoveryGeneration: &authzv3.RevisionRef{Domain: "authz.recovery", Value: strconv.FormatInt(st.recovery, 10)}}
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
