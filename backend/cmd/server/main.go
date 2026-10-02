package main

import (
	besdk "github.com/brickKit/be-sdk-go"
	"github.com/brickKit/infra-authz/v2/backend/module"
)

// 这个文件只有这一行：单跑与进外壳走同一个 module.New，装配逻辑全在 SDK 里。
func main() { besdk.RunStandalone(module.New) }
