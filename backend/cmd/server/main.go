package main

import (
	besdk "github.com/brickKit/be-sdk-go"
	"github.com/brickKit/infra-authz/backend/module"
)

// ⚠️ 这个文件永远只有这一行（§12.5.3、决策 109）。
func main() { besdk.RunStandalone(module.New) }
