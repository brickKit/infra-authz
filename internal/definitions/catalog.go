package definitions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	core "github.com/brickKit/infra-authz/v3/internal/core"

	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/db"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
)

// AttachmentCategories answers the attachment categories of every component's current definitions (CatalogService,
// contract alpha.7; assembly protocol 12): the resource types that declare some, their owner (the component whose
// definitions were accepted: only a resource type's registered owner gets them accepted) and the categories as
// canonical JSON. The revision is a digest of every component's current version: unchanged when the caller holds it.
func AttachmentCategories(m *core.Base, ctx context.Context, in *authzv3.AttachmentCategoriesRequest) (*authzv3.AttachmentCategoriesResponse, error) {
	out := &authzv3.AttachmentCategoriesResponse{}
	err := m.RT.DB.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT component, version FROM authz_component ORDER BY component`)
		if err != nil {
			return err
		}
		var parts []string
		for rows.Next() {
			var c, v string
			if err := rows.Scan(&c, &v); err != nil {
				rows.Close()
				return err
			}
			parts = append(parts, c+"@"+v)
		}
		rows.Close()
		sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
		out.Revision = hex.EncodeToString(sum[:16])
		if in.GetKnownRevision() == out.Revision {
			out.Unchanged = true
			return nil
		}
		rows, err = tx.Query(ctx, `SELECT c.component, d.key, d.record FROM authz_component c
			JOIN authz_definition_set s ON s.component = c.component AND s.version = c.version
			JOIN authz_definition d ON d.digest = ANY(s.digests)
			WHERE d.record_type = 'be.security.resource_definition'`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var owner, key string
			var raw []byte
			if err := rows.Scan(&owner, &key, &raw); err != nil {
				return err
			}
			var rec struct {
				Categories map[string]any `json:"attachment_categories"`
			}
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber() // max_bytes is an integer: canonical encoding refuses floats
			if err := dec.Decode(&rec); err != nil || len(rec.Categories) == 0 {
				continue
			}
			cats, err := canon.Encode(rec.Categories)
			if err != nil {
				return err
			}
			out.Resources = append(out.Resources, &authzv3.ResourceCategories{ResourceType: key, OwnerComponent: owner,
				CategoriesJson: cats})
		}
		return rows.Err()
	})
	sort.Slice(out.Resources, func(i, j int) bool { return out.Resources[i].ResourceType < out.Resources[j].ResourceType })
	return out, err
}
