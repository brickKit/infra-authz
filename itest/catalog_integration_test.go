//go:build integration

package itest

import (
	"encoding/json"
	"testing"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Contract alpha.7, assembly protocol 12: the attachment member reads the attachment categories the accepted
// definitions declare, with their owner and a revision; the same revision answers unchanged; a new version of a
// component's definitions changes it; nobody else may read it.
func TestTheAttachmentCategoryCatalog(t *testing.T) {
	e := startE2E(t)
	t, w, ctx := e.t, e.w, e.ctx
	catalog := authzv3.NewCatalogServiceClient(dial(t, w, "infra/attachment"))
	first, err := catalog.AttachmentCategories(ctx, &authzv3.AttachmentCategoriesRequest{})
	require.NoError(t, err)
	assert.Empty(t, first.GetResources(), "no definition declares categories yet")

	withFiles := *orders
	withFiles.Resources = []sdkauthz.Resource{orders.Resources[0]}
	withFiles.Resources[0].Fields = map[string]sdkauthz.Field{"id": {Class: sdkauthz.Ordinary},
		"total": {Class: sdkauthz.Ordinary}, "contract_file": {Class: sdkauthz.Ordinary}}
	withFiles.Resources[0].AttachmentCategories = map[string]sdkauthz.AttachmentCategory{"demo.order_contract": {
		Field: "contract_file", MaxBytes: 1 << 20, AllowedTypes: []string{"application/pdf"}, Sensitivity: sdkauthz.Normal,
		RetentionClass: "demo_contract", Version: "1"}}
	require.NoError(t, withFiles.Validate())
	require.NoError(t, withFiles.Submit(ctx, authzv3.NewDefinitionServiceClient(dial(t, w, "demo/orders")), w.Deployment, "3.0.9"))

	got, err := catalog.AttachmentCategories(ctx, &authzv3.AttachmentCategoriesRequest{KnownRevision: first.GetRevision()})
	require.NoError(t, err)
	assert.False(t, got.GetUnchanged())
	assert.NotEqual(t, first.GetRevision(), got.GetRevision(), "a new version changes the revision")
	require.Len(t, got.GetResources(), 1)
	r := got.GetResources()[0]
	assert.Equal(t, "demo.order", r.GetResourceType())
	assert.Equal(t, "demo/orders", r.GetOwnerComponent())
	var cats map[string]map[string]any
	require.NoError(t, json.Unmarshal(r.GetCategoriesJson(), &cats))
	assert.Equal(t, "contract_file", cats["demo.order_contract"]["field"])
	assert.EqualValues(t, 1<<20, cats["demo.order_contract"]["max_bytes"])

	again, err := catalog.AttachmentCategories(ctx, &authzv3.AttachmentCategoriesRequest{KnownRevision: got.GetRevision()})
	require.NoError(t, err)
	assert.True(t, again.GetUnchanged())
	assert.Empty(t, again.GetResources())

	_, err = authzv3.NewCatalogServiceClient(dial(t, w, "demo/orders")).AttachmentCategories(ctx,
		&authzv3.AttachmentCategoriesRequest{})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "the attachment member only")
}
