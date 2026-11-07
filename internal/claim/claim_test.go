package claim

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestTheInstallClaimNamesAPrincipalOrACodeDigest: AUTHZ_INSTALL_CLAIM's two forms (A130), nothing else.
func TestTheInstallClaimNamesAPrincipalOrACodeDigest(t *testing.T) {
	kind, value, err := parseClaim("principal:p1")
	assert.NoError(t, err)
	assert.Equal(t, []string{"principal", "p1"}, []string{kind, value})
	digest := "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	kind, value, err = parseClaim("code:sha256:" + digest)
	assert.NoError(t, err)
	assert.Equal(t, "code", kind)
	assert.Equal(t, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", value)
	for _, bad := range []string{"", "principal:", "p1", "code:sha256:abc", "code:sha256:" + digest[:63] + "z", "code:md5:" + digest} {
		_, _, err := parseClaim(bad)
		assert.Error(t, err, bad)
	}
}
