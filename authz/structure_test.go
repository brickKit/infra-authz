package authz

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The guard of the record's lifecycle, as checks (internal/AGENTS.md, "规则只在一处"): a security record's state is
// written only by effectpoint.Transition, which checks every move against the table of internal/effectpoint/
// lifecycle.go; new records are inserted only where registered here, each in a state the table starts from.

var (
	writesRecordState = regexp.MustCompile(`(?is)\bUPDATE\s+authz_record\b.*\bSET\b.*\bstate\s*=`)
	insertsRecord     = regexp.MustCompile(`(?is)\bINSERT\s+INTO\s+authz_record\s*\(`)
)

const transitionFile = "internal/effectpoint/enact.go"

// recordInserts are the places that insert a security record, by file, with what they insert.
var recordInserts = map[string]string{
	"internal/effectpoint/enact.go":      "the effect point's new record, its state checked against the table (Allowed)",
	"internal/claim/claim.go":            "the install claim's root unit, admin holding and grant, active",
	"internal/adminrecovery/recovery.go": "an administrator recovery's admin holding for the identity, active",
}

// sqlLiterals calls f with every string literal of the non-test Go files under internal/, by file relative to the
// repository.
func sqlLiterals(t *testing.T, f func(file string, line int, s string)) {
	root, err := filepath.Abs("..")
	require.NoError(t, err)
	n := 0
	require.NoError(t, filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		n++
		ast.Inspect(file, func(node ast.Node) bool {
			if lit, ok := node.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil {
					f(rel, fset.Position(lit.Pos()).Line, s)
				}
			}
			return true
		})
		return nil
	}))
	require.NotZero(t, n, "the check reads the code under internal/ (else it checks nothing)")
}

// TestOnlyTransitionWritesTheRecordState: no SQL outside effectpoint.Transition's file writes authz_record.state.
func TestOnlyTransitionWritesTheRecordState(t *testing.T) {
	found := 0
	sqlLiterals(t, func(file string, line int, s string) {
		if !writesRecordState.MatchString(s) {
			return
		}
		if file == transitionFile {
			found++
			return
		}
		t.Errorf("%s:%d writes a record's state: use effectpoint.Transition (it checks the move)", file, line)
	})
	assert.Equal(t, 1, found, "Transition is the one writer in "+transitionFile)
}

// TestRecordInsertsAreRegistered: a security record is inserted only where recordInserts says, and each registered
// place still inserts one.
func TestRecordInsertsAreRegistered(t *testing.T) {
	seen := map[string]bool{}
	sqlLiterals(t, func(file string, line int, s string) {
		if !insertsRecord.MatchString(s) {
			return
		}
		seen[file] = true
		if _, ok := recordInserts[file]; !ok {
			t.Errorf("%s:%d inserts a security record: register it in recordInserts with the state it starts in "+
				"(the table's new-record row)", file, line)
		}
	})
	for f := range recordInserts {
		assert.True(t, seen[f], "%s is registered but inserts no record any more: unregister it", f)
	}
}
