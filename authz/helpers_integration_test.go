//go:build integration

package authz

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func dial(t *testing.T, w *sectest.World, component string) *grpc.ClientConn {
	tls := w.TLS(t, component)
	conn, err := grpc.NewClient(itSystem, grpc.WithTransportCredentials(credentials.NewTLS(tls.ClientConfig(ID))))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

func call(t *testing.T, w *sectest.World, who, method, path string, body any) (int, map[string]any) {
	return callAs(t, w.Bearer(who), method, path, body)
}

func callAs(t *testing.T, bearer, method, path string, body any) (int, map[string]any) {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, itBase+path, r)
	req.Header.Set("Authorization", bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]any{"raw": string(b)}
	}
	return resp.StatusCode, out
}

// changePath is where a change request goes: a tightening to its own route (infra.authz.security_record.tighten),
// everything else to the changes.
func changePath(body map[string]any) string {
	if body["direction"] == Tighten {
		return "/api/authz/tightenings"
	}
	return "/api/authz/changes"
}

func submitChange(t *testing.T, w *sectest.World, who string, body map[string]any, want int) map[string]any {
	t.Helper()
	code, out := call(t, w, who, "POST", changePath(body), body)
	require.Equal(t, want, code, "%v: %v", body["change_key"], out)
	return out
}

func listRecords(t *testing.T, w *sectest.World, who, typ string) []map[string]any {
	t.Helper()
	code, out := call(t, w, who, "GET", "/api/authz/records?type="+typ, nil)
	require.Equal(t, 200, code, "%v", out)
	var list []map[string]any
	for _, r := range out["records"].([]any) {
		list = append(list, r.(map[string]any))
	}
	return list
}

// waitForView waits until a principal's new grant on the member's own records is in the member's own view (it
// verifies every 2.5 s): the units are seen through such a grant only (a holder sees its own records, D82; a unit
// is nobody's).
func waitForView(t *testing.T, w *sectest.World, who string) {
	require.Eventually(t, func() bool {
		code, out := call(t, w, who, "GET", "/api/authz/records?type=management_unit", nil)
		recs, _ := out["records"].([]any)
		return code == 200 && len(recs) > 0
	}, 10*time.Second, 200*time.Millisecond)
}

// portFree fails at once when a port the member needs is taken: a running cell (host ports 18xxx) or another member
// would answer in its place, and the test would assert against another process.
func portFree(t *testing.T, addrs ...string) {
	for _, a := range addrs {
		if !strings.Contains(a, ":") {
			a = "localhost:" + a
		}
		ln, err := net.Listen("tcp", a)
		require.NoError(t, err, "port %s is taken: is a cell or another member running?", a)
		_ = ln.Close()
	}
}

// grantReq, unitReq and holdingReq are widenings with their candidate (09a's be.security.change_request); tightenReq
// ends its target.
func widenReq(key, recordType string, candidate map[string]any) map[string]any {
	candidate["record_type"] = recordType
	raw, _ := json.Marshal(candidate)
	return map[string]any{"change_key": key, "direction": "widen", "candidate": json.RawMessage(raw),
		"candidate_digest": candidateDigest(recordType, raw)}
}

func grantReq(key string, unit, grantee any, segs []sdkauthz.Segment) map[string]any {
	return widenReq(key, "grant", map[string]any{"governance_unit": unit, "grantee": grantee, "segments": segs})
}

func unitReq(key string, parent any, name string, scope []sdkauthz.Segment, ops []string) map[string]any {
	return widenReq(key, "management_unit", map[string]any{"parent": parent, "name": name, "managed_scope": scope,
		"grantable_operations": ops})
}

func holdingReq(key string, unit any, holder string) map[string]any {
	return widenReq(key, "management_holding", map[string]any{"unit": unit, "holder": holder})
}

func tightenReq(key string, target any) map[string]any {
	return map[string]any{"change_key": key, "direction": "tighten", "target": target}
}
