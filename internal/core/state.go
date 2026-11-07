package core

import (
	"context"
	"regexp"
	"strconv"

	"github.com/brickKit/be-sdk-go/v3/db"
)

// State is the member's row and the database epoch, read in the view's transaction.
type State struct {
	Recovery, Revision int64  `json:"-"`
	Instance, Epoch    string `json:"-"`
}

func ReadState(ctx context.Context, tx db.Tx) (State, error) {
	var s State
	if err := tx.QueryRow(ctx, "SELECT recovery_generation, security_revision, instance FROM authz_state").
		Scan(&s.Recovery, &s.Revision, &s.Instance); err != nil {
		return s, err
	}
	var g, t int64
	if err := tx.QueryRow(ctx, "SELECT generation, timeline FROM be_current_db_epoch()").Scan(&g, &t); err != nil {
		return s, err
	}
	s.Epoch = strconv.FormatInt(g, 10) + "." + strconv.FormatInt(t, 10)
	return s, nil
}

// Advance moves the deployment's security revision: every effective change does, so every view's digest changes.
func Advance(ctx context.Context, tx db.Tx) error {
	_, err := tx.Exec(ctx, "UPDATE authz_state SET security_revision = security_revision + 1")
	return err
}

var UUIDText = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
