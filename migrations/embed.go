// Package migrations 只做一件事：把这个目录下的 .sql 文件嵌进二进制，
// 供 backend/module 挂到 besdk.Module.Migrations（合并态外壳按拓扑顺序
// 跑，§13.3 铁律五）。
//
// ⚠️ 不能反过来在 backend/module 里直接 //go:embed ../../migrations——
// Go 的 embed 不允许路径里出现 ".."（不管有几层），这是编译期硬限制，
// 不是写法问题。所以嵌入必须挨着这些 .sql 文件本身的目录来做。
//
// 全拆态的迁移容器（backend/cmd/migrate）不读这里——它在运行时直接读
// 磁盘上的 migrations/ 目录（Dockerfile 把这份目录原样拷进镜像），
// 两条路径共用同一份 .sql 文件，不会出现"哪份是权威"的疑问。
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
