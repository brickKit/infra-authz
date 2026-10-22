package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/grpcx"
	"github.com/brickKit/be-sdk-go/v3/records"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/jackc/pgx/v5"
)

// registry is who owns each resource type and permission key (the assembly project's registry, delivered as
// configuration): kind ("resource_type" or "permission") + "\x00" + key -> owner component.
type registry map[string]string

func parseRegistry(tsv string) (registry, error) {
	r := registry{}
	for i, line := range strings.Split(tsv, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "kind\t") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 3 || (f[0] != "resource_type" && f[0] != "permission") {
			return nil, fmt.Errorf("AUTHZ_REGISTRY line %d: want kind, key, owner_component", i+1)
		}
		r[f[0]+"\x00"+f[1]] = f[2]
	}
	return r, nil
}

func (r registry) owner(kind, key string) string { return r[kind+"\x00"+key] }

type rejection struct{ reason, digest, detail string }

// accepted is one definition that passed: its record type, key and fields.
type accepted struct {
	recordType, key, digest string
	raw                     []byte
	body                    map[string]any
}

// Submit is DefinitionService.Submit (contract-infra-authz README, "成员的义务").
func (m *Module) Submit(ctx context.Context, in *authzv3.SubmitRequest) (*authzv3.SubmitResponse, error) {
	if caller, _ := grpcx.Caller(ctx); caller != in.GetComponent() {
		return nil, errs.New(errs.ReasonPermissionDenied, "the component submits only its own definitions").GRPCStatus().Err()
	}
	reg, err := m.registry()
	if err != nil {
		return nil, err
	}
	var bad []rejection
	var defs []accepted
	for _, d := range in.GetDefinitions() {
		a, rej := m.check(in.GetComponent(), d, reg)
		bad = append(bad, rej...)
		if len(rej) == 0 {
			defs = append(defs, a)
		}
	}
	bad = append(bad, crossCheck(defs)...)
	if len(bad) > 0 {
		return rejected(bad), nil
	}
	sealed := make([]sdkauthz.Sealed, len(defs))
	for i, a := range defs {
		sealed[i] = sdkauthz.Sealed{Digest: a.digest}
	}
	set, err := sdkauthz.SetDigest(in.GetComponent(), in.GetVersion(), sealed)
	if err != nil {
		return nil, err
	}
	var conflict bool
	err = m.rt.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var prev string
		err := tx.QueryRow(ctx, "SELECT set_digest FROM authz_definition_set WHERE component = $1 AND version = $2",
			in.GetComponent(), in.GetVersion()).Scan(&prev)
		if err == nil {
			conflict = prev != set
			return nil // the same set again: accepted, nothing to write
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		digests := make([]string, len(defs))
		for i, a := range defs {
			digests[i] = a.digest
			if _, err := tx.Exec(ctx, `INSERT INTO authz_definition (digest, component, record_type, key, record)
				VALUES ($1, $2, $3, $4, $5) ON CONFLICT (digest) DO NOTHING`, a.digest, in.GetComponent(), a.recordType, a.key, a.raw); err != nil {
				return err
			}
		}
		slices.Sort(digests)
		if _, err := tx.Exec(ctx, `INSERT INTO authz_definition_set (component, version, set_digest, digests) VALUES ($1, $2, $3, $4)`,
			in.GetComponent(), in.GetVersion(), set, digests); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO authz_component (component, version) VALUES ($1, $2)
			ON CONFLICT (component) DO UPDATE SET version = EXCLUDED.version, accepted_at = now()`, in.GetComponent(), in.GetVersion()); err != nil {
			return err
		}
		return advance(ctx, tx) // the component's view changes with its definitions
	})
	if err != nil {
		return nil, err
	}
	if conflict {
		return rejected([]rejection{{reason: "DEFINITION_VERSION_CONFLICT",
			detail: "this version was accepted with other definitions; a change of definitions needs a new version"}}), nil
	}
	return &authzv3.SubmitResponse{Status: authzv3.SubmitStatus_SUBMIT_STATUS_ACCEPTED, SetDigest: set}, nil
}

func rejected(bad []rejection) *authzv3.SubmitResponse {
	out := &authzv3.SubmitResponse{Status: authzv3.SubmitStatus_SUBMIT_STATUS_REJECTED}
	for _, r := range bad {
		out.Rejections = append(out.Rejections, &authzv3.Rejection{Reason: r.reason, Digest: r.digest, Detail: r.detail})
	}
	return out
}

// check opens one definition and applies the per-record rules: the schema, the authority, the registry's owners, the
// conditional rules of the field tables, and what this member supports.
func (m *Module) check(component string, d *authzv3.Definition, reg registry) (accepted, []rejection) {
	var head struct {
		RecordType string `json:"record_type"`
	}
	if err := json.Unmarshal(d.GetRecord(), &head); err != nil {
		return accepted{}, []rejection{{"DEFINITION_INVALID", d.GetDigest(), "not JSON"}}
	}
	if head.RecordType != "be.security.resource_definition" && head.RecordType != "be.security.operation_definition" {
		return accepted{}, []rejection{{"DEFINITION_INVALID", d.GetDigest(), "record type " + head.RecordType}}
	}
	body, err := records.Open(head.RecordType, d.GetRecord(), d.GetDigest())
	if err != nil {
		return accepted{}, []rejection{{"DEFINITION_INVALID", d.GetDigest(), err.Error()}}
	}
	a := accepted{recordType: head.RecordType, digest: d.GetDigest(), raw: d.GetRecord(), body: body}
	var bad []rejection
	no := func(reason, detail string) { bad = append(bad, rejection{reason, d.GetDigest(), detail}) }
	if body["authority"] != component {
		no("DEFINITION_OWNER_MISMATCH", fmt.Sprintf("authority %v", body["authority"]))
	}
	if head.RecordType == "be.security.resource_definition" {
		a.key, _ = body["type"].(string)
		if owner := reg.owner("resource_type", a.key); owner != component {
			no("DEFINITION_OWNER_MISMATCH", fmt.Sprintf("resource type %s is registered to %q", a.key, owner))
		}
		fields, _ := body["fields"].(map[string]any)
		for name, f := range fields {
			fd, _ := f.(map[string]any)
			if fd["class"] == "restricted" && fd["read_key"] == nil {
				no("DEFINITION_INVALID", "restricted field "+name+" has no read_key")
			}
		}
		dims, _ := body["dimensions"].(map[string]any)
		for name, dd := range dims {
			dim, _ := dd.(map[string]any)
			if k := dim["kind"]; k == "relation" || k == "record" {
				no("CAPABILITY_UNSUPPORTED", fmt.Sprintf("dimension %s: kind %v is not supported by this member", name, k))
			}
		}
		return a, bad
	}
	a.key, _ = body["key"].(string)
	if owner := reg.owner("permission", a.key); owner != component {
		no("DEFINITION_OWNER_MISMATCH", fmt.Sprintf("permission key %s is registered to %q", a.key, owner))
	}
	if p := body["minimum_path"]; p != "default" {
		no("CAPABILITY_UNSUPPORTED", fmt.Sprintf("operation %s needs the %v path; this member has the default path only", a.key, p))
	}
	if body["tightening_only"] == true {
		effects, _ := body["side_effects"].([]any)
		if body["purpose"] != "manage" || len(effects) != 1 || effects[0] != "security_change" {
			no("DEFINITION_INVALID", "only a manage operation whose only side effect is security_change can be tightening only")
		}
	}
	if body["impersonation_allowed"] == true {
		if effects, _ := body["side_effects"].([]any); len(effects) > 0 {
			no("DEFINITION_INVALID", "an operation with side effects is never allowed under impersonation")
		}
	}
	return a, bad
}

// crossCheck applies the rules across the set: every operation's resource type is defined in it, and every resource
// type's view operation is one of its operations.
func crossCheck(defs []accepted) []rejection {
	types := map[string]bool{}
	ops := map[string]string{}
	for _, a := range defs {
		if a.recordType == "be.security.resource_definition" {
			types[a.key] = true
		} else {
			ops[a.key], _ = a.body["resource_type"].(string)
		}
	}
	var bad []rejection
	for _, a := range defs {
		switch a.recordType {
		case "be.security.operation_definition":
			if rt := ops[a.key]; !types[rt] {
				bad = append(bad, rejection{"DEFINITION_INVALID", a.digest, "resource type " + rt + " is not defined in this submission"})
			}
		case "be.security.resource_definition":
			if v, _ := a.body["view_operation"].(string); ops[v] != a.key {
				bad = append(bad, rejection{"DEFINITION_INVALID", a.digest, "view operation " + v + " is not an operation of " + a.key})
			}
		}
	}
	return bad
}

// advance moves the deployment's security revision: every effective change does, so every view's digest changes.
func advance(ctx context.Context, tx db.Tx) error {
	_, err := tx.Exec(ctx, "UPDATE authz_state SET security_revision = security_revision + 1")
	return err
}
