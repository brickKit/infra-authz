package main

import (
	"github.com/brickKit/be-sdk-go/migrate"
	"github.com/brickKit/infra-authz/v2/migrations"
)

func main() { migrate.Main(migrations.FS) }
