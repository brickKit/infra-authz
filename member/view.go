package member

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/grpcx"
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
	version   string
	resources map[string]map[string]any // type -> fields
	digests   map[string]string         // type -> the resource definition's digest
}

func definitionsOf(ctx context.Context, tx db.Tx, component string) (defined, bool, error) {
	d := defined{resources: map[string]map[string]any{}, digests: map[string]string{}}
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
		if rt != "be.security.resource_definition" {
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			return d, false, err
		}
		d.resources[key], d.digests[key] = body, digest
	}
	return d, d.version != "", rows.Err()
}

// view computes a component's shard from the committed records: canonical bytes and their digest (D76).
func (m *Module) view(ctx context.Context, tx db.Tx, component string) (raw []byte, digest string, st state, ok bool, err error) {
	if st, err = readState(ctx, tx); err != nil {
		return
	}
	defs, ok, err := definitionsOf(ctx, tx, component)
	if err != nil || !ok {
		return nil, "", st, false, err
	}
	grants, err := active(ctx, tx, "grant")
	if err != nil {
		return
	}
	segsOf := map[string][]any{}
	for _, g := range grants {
		var b grantBody
		if err = json.Unmarshal(g.Body, &b); err != nil {
			return
		}
		for _, s := range b.Segments {
			if _, mine := defs.resources[s.ResourceType]; !mine {
				continue
			}
			s.Source = g.ID
			s.Definition, _ = json.Marshal(map[string]any{"owner_component": component, "kind": "resource",
				"key": s.ResourceType, "version": defs.version, "digest": defs.digests[s.ResourceType]})
			c, cerr := s.Canonical(s.ResourceType)
			if cerr != nil {
				err = cerr
				return
			}
			segsOf[b.Grantee] = append(segsOf[b.Grantee], c)
		}
	}
	subjects := map[string]any{}
	for p, segs := range segsOf {
		set, serr := canon.SortedSet(segs)
		if serr != nil {
			err = serr
			return
		}
		// no identity events yet (step 5): an account's disabling reaches views with the change pull, later
		subjects[p] = map[string]any{"segments": set, "accounts_disabled": false}
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
	return raw, digest, st, true, err
}

// Verify is ViewService.Verify (contract-infra-authz README): recomputed on the primary for every request, never
// cached; the held digest equal to the current one is unchanged, anything else gets the current view.
func (m *Module) Verify(ctx context.Context, in *authzv3.VerifyRequest) (*authzv3.VerifyResponse, error) {
	if caller, _ := grpcx.Caller(ctx); caller != in.GetComponent() {
		return nil, errs.New(errs.ReasonPermissionDenied, "a component verifies only its own view").GRPCStatus().Err()
	}
	var raw []byte
	var digest string
	var st state
	var ok bool
	err := m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		raw, digest, st, ok, err = m.view(ctx, tx, in.GetComponent())
		return err
	}, db.Serializable())
	if err != nil {
		return nil, err
	}
	shard := shardOf(in.GetComponent())
	out := &authzv3.VerifyResponse{Nonce: in.GetNonce(), ComputedAt: canon.Time(time.Now()), Instance: st.instance,
		RecoveryGeneration: &authzv3.RevisionRef{Domain: "authz.recovery", Value: strconv.FormatInt(st.recovery, 10)}}
	switch {
	case !ok: // no accepted definitions: nothing can be proven for this component yet
		out.Shards = append(out.Shards, &authzv3.ShardAnswer{Shard: shard, Status: authzv3.ShardStatus_SHARD_STATUS_CLOSED})
	case heldDigest(in, shard) == digest:
		out.Shards = append(out.Shards, &authzv3.ShardAnswer{Shard: shard, Status: authzv3.ShardStatus_SHARD_STATUS_UNCHANGED})
	default:
		out.Shards = append(out.Shards, &authzv3.ShardAnswer{Shard: shard, Status: authzv3.ShardStatus_SHARD_STATUS_CHANGED,
			View: raw, Digest: digest})
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
