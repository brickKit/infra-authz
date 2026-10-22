// Command infra-authz runs the authorization member alone (serve, migrate); the shells compile in authz.Definition().
package main

import (
	"github.com/brickKit/be-sdk-go/v3/launcher"
	"github.com/brickKit/infra-authz/v3/authz"
)

func main() { launcher.Main(authz.Definition()) }
