// Command infra-authz runs the authorization member alone (serve, migrate); the shells compile in member.Definition().
package main

import (
	"github.com/brickKit/be-sdk-go/v3/launcher"
	"github.com/brickKit/infra-authz/v3/member"
)

func main() { launcher.Main(member.Definition()) }
