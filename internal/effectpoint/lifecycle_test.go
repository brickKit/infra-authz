package effectpoint

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTheDesignDocumentHasTheMoves: docs/design.md's "记录的状态迁移" is the table moves, row by row.
func TestTheDesignDocumentHasTheMoves(t *testing.T) {
	doc, err := os.ReadFile("../../docs/design.md")
	require.NoError(t, err)
	tick := regexp.MustCompile("`([a-z_/]+)`")
	sec := string(doc)
	start := strings.Index(sec, "## 记录的状态迁移")
	require.GreaterOrEqual(t, start, 0)
	sec = sec[start:]
	sec = sec[:strings.Index(sec, "\n说明：")]
	seen := map[string]bool{}
	for _, line := range strings.Split(sec, "\n") {
		cells := strings.Split(strings.Trim(line, "| "), " | ")
		if !strings.HasPrefix(line, "| ") || len(cells) != 2 || cells[0] == "从" || strings.HasPrefix(cells[0], "---") {
			continue
		}
		from := ""
		if m := tick.FindStringSubmatch(cells[0]); m != nil {
			from = m[1]
		}
		var to []string
		for _, m := range tick.FindAllStringSubmatch(cells[1], -1) {
			to = append(to, m[1])
		}
		want, ok := moves[from]
		require.True(t, ok, "the document has a state the code does not: %q", from)
		assert.Equal(t, sorted(want), sorted(to), "from %q: the document and the code differ", from)
		seen[from] = true
	}
	assert.Len(t, seen, len(moves), "the document has every row of the table")
}

func sorted(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	if out == nil {
		out = []string{}
	}
	return out
}

// TestTheTransitionsTheSuiteMakes: every move the integration suite made when the table was written (a probe in
// Transition, 2026-11-07) is allowed; a change that refuses one of them changes behaviour.
func TestTheTransitionsTheSuiteMakes(t *testing.T) {
	for _, m := range [][5]string{
		{"awaiting_confirmation", "", "active", "", ""}, {"active", "", "ended", "revoked", ""},
		{"active", "", "held", "", "security_hold"}, {"held", "security_hold", "active", "", ""},
		{"active", "", "ended", "source_ended", ""}, {"scheduled", "", "ended", "cancelled", ""},
		{"scheduled", "", "active", "", ""}, {"active", "", "ended", "relinquished", ""},
		{"active", "", "ended", "superseded", ""}, {"awaiting_confirmation", "", "scheduled", "", ""},
		{"active", "", "held", "", "uncomputable"}, {"scheduled", "", "ended", "withdrawn", ""},
		{"scheduled", "", "ended", "rejected", ""}, {"held", "uncomputable", "active", "", ""},
		{"awaiting_confirmation", "", "ended", "cancelled", ""}, {"held", "security_hold", "held", "", "restore_pending"},
		{"held", "security_hold", "ended", "revoked", ""}, {"awaiting_confirmation", "", "ended", "withdrawn", ""},
		{"awaiting_confirmation", "", "ended", "rejected", ""}, {"awaiting_confirmation", "", "awaiting_confirmation", "", ""},
		{"active", "", "ended", "source_narrowed", ""}, {"active", "", "ended", "expired", ""},
		{"held", "security_hold", "ended", "superseded", ""}, {"held", "security_hold", "ended", "relinquished", ""},
		{"held", "restore_pending", "ended", "source_narrowed", ""},
	} {
		assert.True(t, Allowed(m[0], m[1], m[2], m[3], m[4]), "%v", m)
	}
}

// TestEndedIsFinal: an ended record never moves (security 08: never revived); nothing but a new record is requested; a
// record is never moved to held as uncomputable from held, nor to restore_pending but from a disposition's hold.
func TestEndedIsFinal(t *testing.T) {
	assert.Empty(t, moves["ended"])
	for from, to := range moves {
		if from != "" { // only a new record (a draft or a suggestion) is requested
			assert.NotContains(t, to, "requested", "from %q", from)
		}
		if strings.HasPrefix(from, "held/") {
			assert.NotContains(t, to, "held/uncomputable", "from %q", from)
		}
		if from != "held/security_hold" {
			assert.NotContains(t, to, "held/restore_pending", "from %q", from)
		}
	}
	assert.False(t, Allowed("ended", "", "active", "", ""))
	assert.False(t, Allowed("active", "", "awaiting_confirmation", "", ""))
}
