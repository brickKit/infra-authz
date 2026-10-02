// Package migrations 把本目录的 .sql 文件嵌进二进制：backend/cmd/migrate 的
// migrate.Main(migrations.FS) 从这里读，镜像里不需要另拷迁移文件。
//
// 嵌入必须挨着 .sql 所在的目录做：Go 的 //go:embed 不允许路径里出现 ".."，
// 不能从 backend/ 下反过来嵌 ../../migrations。
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
